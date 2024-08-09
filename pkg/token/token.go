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
	TokenParent:           "Parent",
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

func NewToken(t Type, expiration time.Time, maxTTL time.Duration, policies []string, meta map[string]string) *Token {
	return &Token{T: t, Expiration: expiration, MaxTTL: maxTTL, Policies: policies, Metadata: meta}
}

type Token struct {
	T          Type
	Expiration time.Time
	Policies   []string
	Parent     string
	Metadata   map[string]string
	MaxTTL     time.Duration
}

func (t *Token) GetType() Type {
	return t.T
}

func (t *Token) GetExpiration() time.Time {
	return t.Expiration
}

func (t *Token) GetPolicies() []string {
	return t.Policies
}

func (t *Token) GetParent() string {
	return t.Parent
}

func (t *Token) GetMetadata() map[string]string {
	return t.Metadata
}
