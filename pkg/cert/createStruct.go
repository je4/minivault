package cert

type CreateStruct struct {
	Type     string   `json:"type" example:"client_cert"`
	URIs     []string `json:"uris" example:"uri1,uri2"`
	DNSNames []string `json:"dnnames" example:"dns1,dns2"`
	TTL      string   `json:"ttl" example:"1h"`
}
