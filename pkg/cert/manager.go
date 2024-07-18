package cert

import (
	"net"
	"time"
)

type Manager interface {
	Create(client, server bool, uris []string, ips []net.IP, dns []string, ttl time.Duration) (cert []byte, key []byte, err error)
}
