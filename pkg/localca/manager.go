package localca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"emperror.dev/errors"
	"encoding/pem"
	"github.com/je4/minivault/v2/pkg/cert"
	"github.com/je4/trustutil/v2/pkg/certutil"
	"github.com/je4/utils/v2/pkg/zLogger"
	"net"
	"time"
)

func NewManager(ca *x509.Certificate, cakey any, name *pkix.Name, keyType certutil.KeyType, maxTTL time.Duration, logger zLogger.ZLogger) *Manager {
	return &Manager{
		ca:      ca,
		caPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
		caKey:   cakey,
		name:    name,
		keyType: keyType,
		maxTTL:  maxTTL,
		logger:  logger,
	}
}

type Manager struct {
	ca      *x509.Certificate
	caKey   any
	name    *pkix.Name
	logger  zLogger.ZLogger
	keyType certutil.KeyType
	caPEM   string
	maxTTL  time.Duration
}

func (m *Manager) GetCAPEM() string {
	return m.caPEM
}

func (m *Manager) Create(client, server bool, uris []string, ips []net.IP, dns []string, ttl time.Duration) (cert []byte, key []byte, err error) {
	if ttl > m.maxTTL {
		return nil, nil, errors.Errorf("ttl %s is greater than max ttl %s", ttl.String(), m.maxTTL.String())
	}
	return certutil.CreateCertificate(
		client,
		server,
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
