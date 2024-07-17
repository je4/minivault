package cert

import (
	"net"
	"time"
)

type Manager interface {
	GetClient(uris []string, ttl time.Duration) (cert []byte, key []byte, err error)
	GetServer(ips []net.IP, dns []string, ttl time.Duration) (cert []byte, key []byte, err error)
	GetHybrid(uris []string, ips []net.IP, dns []string, ttl time.Duration) (cert []byte, key []byte, err error)
}
