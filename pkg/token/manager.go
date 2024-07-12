package token

import (
	"context"
	"emperror.dev/errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

type CreateStruct struct {
	Type      string            `json:"type"`
	Policies  []string          `json:"policies"`
	Meta      map[string]string `json:"meta"`
	TTL       string            `json:"ttl"`
	Renewable bool              `json:"renewable"`
}

func NewManager(store Store, xor uint64) *Manager {
	return &Manager{
		Mutex: sync.Mutex{},
		store: store,
		xor:   xor,
	}
}

type Manager struct {
	sync.Mutex
	store Store
	xor   uint64
}

func (m *Manager) Create(parent string, options *CreateStruct) (string, error) {
	// make sure, that the token is unique
	m.Lock()
	time.Sleep(2 * time.Nanosecond)
	m.Unlock()

	t, ok := StringType[options.Type]
	if !ok {
		return "", errors.Errorf("unknown token type %s", options.Type)
	}
	ttl, err := time.ParseDuration(options.TTL)
	if err != nil {
		return "", errors.Wrapf(err, "cannot parse duration %s", options.TTL)
	}

	now := time.Now()
	exp := now.Add(ttl)

	var parentToken *Token
	if parent != "" {
		p, err := m.store.Get(context.Background(), parent)
		if err != nil {
			return "", errors.Wrapf(err, "cannot get parent token %s", parent)
		}
		if p == nil {
			return "", errors.Errorf("parent token %s not found", parent)
		}
		parentToken = &Token{}
		if err := parentToken.UnmarshalBinary(p); err != nil {
			return "", errors.Wrap(err, "cannot unmarshal parent token")
		}
		if parentToken.Expiration().Before(time.Now()) {
			return "", errors.Errorf("parent token %s expired", parent)
		}
		// Todo: optimize code
		for _, p := range options.Policies {
			if !slices.Contains(parentToken.Policies(), p) {
				return "", errors.Errorf("parent token %s has no policy %s", parent, p)
			}
		}
		if parentToken.Expiration().Before(exp) {
			return "", errors.Errorf("parent token %s expires before child token", parent)
		}
	}

	// generate unique name, looks random but is not...
	name := fmt.Sprintf("s.%d", uint64(now.UnixNano())^m.xor)
	token := NewToken(t, now.Add(ttl), options.Policies)
	tokenBin, err := token.MarshalBinary()
	if err != nil {
		return "", errors.Wrap(err, "cannot marshal token")
	}
	if err := m.store.Put(context.Background(), name, tokenBin, ttl); err != nil {
		return "", errors.Wrap(err, "cannot store token")
	}
	return name, nil
}
