package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"emperror.dev/errors"
	"encoding/json"
	"encoding/pem"
	"github.com/je4/minivault/v2/pkg/cert"
	"github.com/je4/minivault/v2/pkg/rest"
	"github.com/je4/minivault/v2/pkg/token"
	"io"
	"net/http"
)

func NewClient(baseURL string, certPool *x509.CertPool) *Client {
	return &Client{
		baseURL: baseURL,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
				},
			},
		},
	}
}

type Client struct {
	*http.Client
	baseURL string
}

func (c *Client) CreateToken(parentToken string, param *token.CreateStruct) (string, error) {
	data, err := json.Marshal(param)
	if err != nil {
		return "", errors.Wrap(err, "cannot marshal token creation data")
	}
	req, err := http.NewRequest("POST", c.baseURL+"/auth/token/create", bytes.NewBuffer(data))
	if err != nil {
		return "", errors.Wrap(err, "cannot create request")
	}
	req.Header.Set("X-Vault-Token", parentToken)
	resp, err := c.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "cannot get token")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if result, err := io.ReadAll(resp.Body); err == nil {
			return "", errors.Errorf("cannot get token: %s - %s", resp.Status, string(result))
		} else {
			return "", errors.Wrapf(err, "cannot get token: %s", resp.Status)
		}
	}
	var result string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", errors.Wrap(err, "cannot decode token")
	}
	return result, nil
}

type CertResultMessage struct {
	Cert *tls.Certificate

	CA *x509.Certificate
}

func (c *Client) CreateCert(token string, param *cert.CreateStruct) (*CertResultMessage, error) {
	data, err := json.Marshal(param)
	if err != nil {
		return nil, errors.Wrap(err, "cannot marshal cert creation data")
	}
	req, err := http.NewRequest("POST", c.baseURL+"/cert/create", bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.Wrap(err, "cannot create request")
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := c.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get cert")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if result, err := io.ReadAll(resp.Body); err == nil {
			return nil, errors.Errorf("cannot get cert: %s - %s", resp.Status, string(result))
		} else {
			return nil, errors.Wrapf(err, "cannot get cert: %s", resp.Status)
		}
	}
	var result = rest.CertResultMessage{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "cannot decode cert")
	}

	var ret = &CertResultMessage{}
	if result.Cert != "" && result.Key != "" {
		crt, err := tls.X509KeyPair([]byte(result.Cert), []byte(result.Key))
		if err != nil {
			return nil, errors.Wrap(err, "cannot create x509 key pair")
		}
		ret.Cert = &crt
	}
	if result.CA != "" {
		certData, _ := pem.Decode([]byte(result.Cert))
		if certData == nil {
			return nil, errors.New("cannot decode certificate")
		}
		if certData.Type != "CERTIFICATE" {
			return nil, errors.New("no certificate found")
		}
		ca, err := x509.ParseCertificate(certData.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, "cannot parse ca certificate")
		}
		ret.CA = ca
	}
	return ret, nil
}

func (c *Client) GetCA() (*x509.CertPool, error) {
	req, err := http.NewRequest("GET", c.baseURL+"/cert/ca/pem", nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create request")
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "cannot get ca")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if result, err := io.ReadAll(resp.Body); err != nil {
			return nil, errors.Errorf("cannot get ca: %s - %s", resp.Status, string(result))
		} else {
			return nil, errors.Wrapf(err, "cannot get ca: %s", resp.Status)
		}
	}
	var result = rest.CertResultMessage{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "cannot decode ca")
	}
	if result.CA == "" {
		return nil, errors.New("no ca certificate found")
	}
	certData, _ := pem.Decode([]byte(result.CA))
	if certData == nil {
		return nil, errors.New("cannot decode certificate")
	}
	if certData.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate found")
	}
	ca, err := x509.ParseCertificate(certData.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "cannot parse ca certificate")
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca)
	return caCertPool, nil

}
