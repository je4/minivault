package policy

import "time"

func NewPolicy(name string, uris []string, dns []string, maxTTL time.Duration) *Policy {
	return &Policy{
		Name:   name,
		URIs:   uris,
		DNS:    dns,
		MaxTTL: maxTTL,
	}
}

type Policy struct {
	Name   string        `json:"name" toml:"name" yaml:"name"`
	URIs   []string      `json:"uris" toml:"uris" yaml:"uris"`
	DNS    []string      `json:"dns" toml:"dns" yaml:"dns"`
	MaxTTL time.Duration `json:"maxttl" toml:"maxttl" yaml:"maxttl"`
}
