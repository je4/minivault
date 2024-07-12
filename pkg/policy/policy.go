package policy

func NewPolicy(name string, uris []string, dns []string) *Policy {
	return &Policy{
		Name: name,
		URIs: uris,
		DNS:  dns,
	}
}

type Policy struct {
	Name string   `json:"name" toml:"name" yaml:"name"`
	URIs []string `json:"uris" toml:"uris" yaml:"uris"`
	DNS  []string `json:"dns" toml:"dns" yaml:"dns"`
}
