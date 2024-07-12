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

var TypeString map[Type]string = map[Type]string{
	TokenServerCert:       "server_cert",
	TokenClientCert:       "client_cert",
	TokenClientServerCert: "client_server_cert",
}

var StringType map[string]Type = map[string]Type{
	"server_cert":        TokenServerCert,
	"client_cert":        TokenClientCert,
	"client_server_cert": TokenClientServerCert,
}

func NewToken(t Type, expiration time.Time, policies []string) *Token {
	return &Token{t: t, expiration: expiration, policies: policies}
}

type Token struct {
	t          Type
	expiration time.Time
	policies   []string
	parent     string
	metadata   map[string]string
}

func (t *Token) Type() Type {
	return t.t
}

func (t *Token) Expiration() time.Time {
	return t.expiration
}

func (t *Token) Policies() []string {
	return t.policies
}

func (t *Token) Parent() string {
	return t.parent
}

func (t *Token) Metadata() map[string]string {
	return t.metadata
}
