package tresor

import (
	"time"

	"github.com/openservicemesh/osm/pkg/certificate"
)

// GetCommonName implements certificate.Certificater and returns the CN of the cert.
func (c Certificate) GetCommonName() certificate.CommonName {
	return c.commonName
}

// GetCertificateChain implements certificate.Certificater and returns the certificate chain.
func (c Certificate) GetCertificateChain() []byte {
	return c.certChain
}

// GetPrivateKey implements certificate.Certificater and returns the private key of the cert.
func (c Certificate) GetPrivateKey() []byte {
	return c.privateKey
}

// GetIssuingCA implements certificate.Certificater and returns the root certificate for the given cert.
func (c Certificate) GetIssuingCA() []byte {
	return c.issuingCA
}

// GetExpiration implements certificate.Certificater and returns the time the given certificate expires.
func (c Certificate) GetExpiration() time.Time {
	return c.expiration
}

// GetSerialNumber returns the serial number of the given certificate.
func (c Certificate) GetSerialNumber() certificate.SerialNumber {
	return c.serialNumber
}

// NewCertManager creates a new CertManager with the passed CA and CA Private Key
func NewCertManager(options Options) (*CertManager, error) {
	//TODO(steeling): Make sure the options are validated.
	return &CertManager{
		// The root certificate signing all newly issued certificates
		ca:                          options.ca,
		certificatesOrganization:    options.certificatesOrganization,
		serviceCertValidityDuration: options.ServiceCertValidityDuration,
		keySize:                     options.KeySize,
		msgBroker:                   options.MsgBroker,
	}, nil
}
