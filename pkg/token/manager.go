package token

import (
	"context"
	"crypto/rand"
	"emperror.dev/errors"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"time"
)

type CreateStruct struct {
	Type      string            `json:"type" example:"client_cert"`
	Policies  []string          `json:"policies" example:"policy1,policy2"`
	Meta      map[string]string `json:"meta" example:"key1:value1,key2:value2"`
	TTL       string            `json:"ttl" example:"1h"`
	Renewable bool              `json:"renewable" example:"false"`
}

func NewManager(store Store, xor uint64, rndSize int) *Manager {
	return &Manager{
		Mutex:   sync.Mutex{},
		store:   store,
		xor:     xor,
		rndSize: rndSize,
	}
}

type Manager struct {
	sync.Mutex
	store   Store
	xor     uint64
	rndSize int
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
		if parentToken.Type() == TokenRoot {
			if t != TokenParent {
				return "", errors.Errorf("root token %s cannot have child tokens", parent)
			}
		} else {
			if parentToken.Type() != TokenParent {
				return "", errors.Errorf("parent token %s is not a parent token", parent)
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
	}

	// generate unique name, looks random but is not...
	rndData := make([]byte, m.rndSize)
	if _, err := rand.Read(rndData); err != nil {
		return "", errors.Wrap(err, "cannot generate random data")
	}
	name := fmt.Sprintf("%s.%d.%s", TypePrefix[t], uint64(now.UnixNano())^m.xor, hex.EncodeToString(rndData))
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
