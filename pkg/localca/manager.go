package localca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/je4/minivault/v2/pkg/cert"
	"github.com/je4/trustutil/v2/pkg/certutil"
	"github.com/je4/utils/v2/pkg/zLogger"
	"net"
	"time"
)

func NewManager(ca *x509.Certificate, cakey any, name *pkix.Name, keyType certutil.KeyType, logger zLogger.ZLogger) *Manager {
	return &Manager{
		ca:      ca,
		caKey:   cakey,
		name:    name,
		keyType: keyType,
		logger:  logger,
	}
}

type Manager struct {
	ca      *x509.Certificate
	caKey   any
	name    *pkix.Name
	logger  zLogger.ZLogger
	keyType certutil.KeyType
}

func (m *Manager) GetClient(uris []string, ttl time.Duration) (cert []byte, key []byte, err error) {
	return certutil.CreateCertificate(
		true,
		false,
		ttl,
		m.ca,
		m.caKey,
		[]net.IP{},
		[]string{},
		[]string{},
		uris,
		m.name,
		m.keyType,
	)
}

func (m *Manager) GetServer(ips []net.IP, dns []string, ttl time.Duration) (cert []byte, key []byte, err error) {
	return certutil.CreateCertificate(
		false,
		true,
		ttl,
		m.ca,
		m.caKey,
		ips,
		dns,
		[]string{},
		[]string{},
		m.name,
		m.keyType,
	)
}

func (m *Manager) GetHybrid(uris []string, ips []net.IP, dns []string, ttl time.Duration) (cert []byte, key []byte, err error) {
	return certutil.CreateCertificate(
		true,
		true,
		ttl,
		m.ca,
		m.caKey,
		ips,
		dns,
		[]string{},
		uris,
		m.name,
		m.keyType,
	)
}

var _ cert.Manager = (*Manager)(nil)
