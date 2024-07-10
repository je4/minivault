package token

import (
	"time"
)

type Type uint16

const (
	TokenServerCert Type = iota
	TokenClientCert
	TokenClientServerCert
)

func NewToken(t Type, expiration time.Time, uris, names []string) *Token {
	return &Token{t: t, expiration: expiration, uris: uris, names: names}
}

type Token struct {
	t          Type
	expiration time.Time
	uris       []string
	names      []string
}

func (t *Token) Type() Type {
	return t.t
}

func (t *Token) Expiration() time.Time {
	return t.expiration
}

func (t *Token) URIs() []string {
	return t.uris
}

func (t *Token) Names() []string {
	return t.names
}
