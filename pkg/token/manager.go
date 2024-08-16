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
	Policies  []string          `json:"Policies" example:"policy1,policy2"`
	Meta      map[string]string `json:"meta" example:"key1:value1,key2:value2"`
	TTL       string            `json:"ttl" example:"1000h"`
	MaxTTL    string            `json:"maxttl" example:"3h"`
	Renewable bool              `json:"renewable" example:"false"`
}

func NewManager(store Store, xor uint64, tokenMaxTTL time.Duration, certMaxTTL time.Duration, parentMaxTTL time.Duration, rndSize int) *Manager {
	return &Manager{
		Mutex:        sync.Mutex{},
		store:        store,
		xor:          xor,
		tokenMaxTTL:  tokenMaxTTL,
		certMaxTTL:   certMaxTTL,
		parentMaxTTL: parentMaxTTL,
		rndSize:      rndSize,
	}
}

type Manager struct {
	sync.Mutex
	store        Store
	xor          uint64
	rndSize      int
	tokenMaxTTL  time.Duration
	certMaxTTL   time.Duration
	parentMaxTTL time.Duration
}

func (m *Manager) Get(name string) (*Token, error) {
	data, err := m.store.Get(context.Background(), name)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get token")
	}
	if data == nil {
		return nil, nil
	}
	token := &Token{}
	if err := token.UnmarshalBinary(data); err != nil {
		return nil, errors.Wrap(err, "cannot unmarshal token")
	}
	return token, nil
}

func (m *Manager) Delete(name string) error {
	if err := m.store.Delete(context.Background(), name); err != nil {
		return errors.Wrapf(err, "cannot delete token %s", name)
	}
	return nil
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
	var ttl time.Duration
	var maxTTL time.Duration
	var err error
	now := time.Now()
	var exp time.Time

	var parentToken *Token
	if t == TokenParent || t == TokenRoot {
		if parent != "" {
			return "", errors.Errorf("parent or root token cannot have a parent")
		}
		ttl = m.parentMaxTTL
		if options.TTL != "" {
			ttl, err = time.ParseDuration(options.TTL)
			if err != nil {
				return "", errors.Wrapf(err, "cannot parse parent token TTL duration %s", options.TTL)
			}
		}
		if ttl > m.parentMaxTTL {
			return "", errors.Errorf("parent token ttl %s is greater than max ttl %s", ttl.String(), m.tokenMaxTTL.String())
		}
		maxTTL = m.tokenMaxTTL
		if options.MaxTTL != "" {
			maxTTL, err = time.ParseDuration(options.MaxTTL)
			if err != nil {
				return "", errors.Wrapf(err, "cannot parse token maxTTL duration %s", options.MaxTTL)
			}
		}
		if maxTTL > m.tokenMaxTTL {
			return "", errors.Errorf("token max ttl %s is greater than max ttl %s", maxTTL.String(), m.tokenMaxTTL.String())
		}
		exp = now.Add(ttl)
	} else {
		if parent == "" {
			return "", errors.Errorf("standard token needs a parent")
		}
		ttl = m.tokenMaxTTL
		if options.TTL != "" {
			ttl, err = time.ParseDuration(options.TTL)
			if err != nil {
				return "", errors.Wrapf(err, "cannot parse token TTL duration %s", options.TTL)
			}
		}
		if ttl > m.tokenMaxTTL {
			return "", errors.Errorf("token ttl %s is greater than max ttl %s", ttl.String(), m.tokenMaxTTL.String())
		}
		maxTTL = m.certMaxTTL
		if options.MaxTTL != "" {
			maxTTL, err = time.ParseDuration(options.MaxTTL)
			if err != nil {
				return "", errors.Wrapf(err, "cannot parse cert maxTTL duration %s", options.MaxTTL)
			}
		}
		if maxTTL > m.certMaxTTL {
			return "", errors.Errorf("cert max ttl %s is greater than max ttl %s", maxTTL.String(), m.certMaxTTL.String())
		}
		exp = now.Add(ttl)
		p, err := m.store.Get(context.Background(), parent)
		if err != nil {
			return "", errors.Wrapf(err, "cannot get Parent token %s", parent)
		}
		if p == nil {
			return "", errors.Errorf("Parent token %s not found", parent)
		}
		parentToken = &Token{}
		if err := parentToken.UnmarshalBinary(p); err != nil {
			return "", errors.Wrap(err, "cannot unmarshal Parent token")
		}
		if parentToken.GetExpiration().Before(time.Now()) {
			return "", errors.Errorf("Parent token %s expired", parent)
		}
		if parentToken.GetType() == TokenRoot {
			if t != TokenParent {
				return "", errors.Errorf("root token %s cannot have child tokens", parent)
			}
		} else {
			if parentToken.GetType() != TokenParent {
				return "", errors.Errorf("Parent token %s is not a Parent token", parent)
			}
			// Todo: optimize code
			parentPolicies := parentToken.GetPolicies()
			for _, p := range options.Policies {
				if !slices.Contains(parentPolicies, p) {
					return "", errors.Errorf("Parent token %s has no policy %s", parent, p)
				}
			}
			if parentToken.GetExpiration().Before(exp) {
				return "", errors.Errorf("Parent token %s expires before child token", parent)
			}
		}
	}

	// generate unique name, looks random but is not...
	rndData := make([]byte, m.rndSize)
	if _, err := rand.Read(rndData); err != nil {
		return "", errors.Wrap(err, "cannot generate random data")
	}
	name := fmt.Sprintf("%s.%x.%s", TypePrefix[t], uint64(now.UnixNano())^m.xor, hex.EncodeToString(rndData))
	token := NewToken(t, now.Add(ttl), maxTTL, options.Policies, options.Meta)
	tokenBin, err := token.MarshalBinary()
	if err != nil {
		return "", errors.Wrap(err, "cannot marshal token")
	}
	if err := m.store.Put(context.Background(), name, tokenBin, ttl); err != nil {
		return "", errors.Wrap(err, "cannot store token")
	}
	return name, nil
}
