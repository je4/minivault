package token

import (
	"time"
)

type Type uint16

const (
	TokenRoot Type = iota
	TokenParent
	TokenServerCert
	TokenClientCert
	TokenClientServerCert
)

var TypeString map[Type]string = map[Type]string{
	TokenRoot:             "root",
	TokenParent:           "parent",
	TokenServerCert:       "server_cert",
	TokenClientCert:       "client_cert",
	TokenClientServerCert: "client_server_cert",
}

var TypePrefix map[Type]string = map[Type]string{
	TokenRoot:             "ro",
	TokenParent:           "pa",
	TokenServerCert:       "sc",
	TokenClientCert:       "cc",
	TokenClientServerCert: "cs",
}

var StringType map[string]Type = map[string]Type{
	"server_cert":        TokenServerCert,
	"client_cert":        TokenClientCert,
	"client_server_cert": TokenClientServerCert,
	"parent":             TokenParent,
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
