package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// CommonFields represents common X.509 certificate fields
type CommonFields struct {
	CommonName string `toml:"common_name"`

	Country          []string `toml:"country"`
	Organization     []string `toml:"organization"`
	OrganizationUnit []string `toml:"organization_unit"`

	Locality []string `toml:"locality"`
	Province []string `toml:"province"`

	StreetAddress []string `toml:"street_address"`
	PostalCode    []string `toml:"postal_code"`
}

func (c *CommonFields) ToPKIXName() pkix.Name {
	return pkix.Name{
		Country:            c.Country,
		Organization:       c.Organization,
		OrganizationalUnit: c.OrganizationUnit,
		Locality:           c.Locality,
		Province:           c.Province,
		StreetAddress:      c.StreetAddress,
		PostalCode:         c.PostalCode,
		CommonName:         c.CommonName,
	}
}

type Params struct {
	ValidityPeriod time.Duration
	KeySize        int

	CommonFields
	SubjectAdditionalNames
}

func (c *Params) GenKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, c.KeySize)
}

func (c *Params) CSRTemplate() *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject:        c.CommonFields.ToPKIXName(),
		DNSNames:       c.DNSNames,
		EmailAddresses: c.EmailAddresses,
		IPAddresses:    c.IPAddresses,
		URIs:           c.URLs,
	}
}

func (c *Params) CACertTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().Add(c.ValidityPeriod).UTC(),
		BasicConstraintsValid: true,
		IsCA:     true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		Subject:  c.ToPKIXName(),
	}
}

func (c *Params) CertTemplate() *x509.Certificate {
	return &x509.Certificate{
		NotBefore: time.Now().UTC(),
		NotAfter: func() time.Time {
			if c.ValidityPeriod == 0 {
				return time.Time{}
			}
			return time.Now().Add(c.ValidityPeriod).UTC()
		}(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           c.IPAddresses,
		DNSNames:              c.DNSNames,
		URIs:                  c.URLs,
		EmailAddresses:        c.EmailAddresses,
	}
}
