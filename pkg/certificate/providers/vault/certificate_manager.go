package vault

import (
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/certificate/pem"
	"github.com/openservicemesh/osm/pkg/certificate/rotor"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/errcode"
	"github.com/openservicemesh/osm/pkg/logger"
)

var log = logger.New("vault")

const (
	// The string value of the JSON key containing the certificate's Serial Number.
	// See: https://www.vaultproject.io/api-docs/secret/pki#sample-response-8
	serialNumberField = "serial_number"
	certificateField  = "certificate"
	privateKeyField   = "private_key"
	issuingCAField    = "issuing_ca"
	commonNameField   = "common_name"
	ttlField          = "ttl"

	checkCertificateExpirationInterval = 5 * time.Second
	decade                             = 8765 * time.Hour
)

// NewCertManager implements certificate.Manager and wraps a Hashi Vault with methods to allow easy certificate issuance.
func NewCertManager(
	vaultAddr,
	token string,
	role string) (*CertManager, error) {
	c := &CertManager{
		role: vaultRole(role),
	}
	config := api.DefaultConfig()
	config.Address = vaultAddr

	var err error
	if c.client, err = api.NewClient(config); err != nil {
		return nil, errors.Errorf("Error creating Vault CertManager without TLS at %s", vaultAddr)
	}

	log.Info().Msgf("Created Vault CertManager, with role=%q at %v", role, vaultAddr)

	c.client.SetToken(token)

	issuingCA, serialNumber, err := c.getIssuingCA(c.issue)
	if err != nil {
		return nil, err
	}

	c.ca = &certificate.Certificate{
		CommonName:   constants.CertificationAuthorityCommonName,
		SerialNumber: serialNumber,
		Expiration:   time.Now().Add(decade),
		CertChain:    issuingCA,
		IssuingCA:    issuingCA,
	}

	// Instantiating a new certificate rotation mechanism will start a goroutine for certificate rotation.
	rotor.New(c).Start(checkCertificateExpirationInterval)

	return c, nil
}

func (cm *CertManager) getIssuingCA(issue func(certificate.CommonName, time.Duration) (*certificate.Certificate, error)) ([]byte, certificate.SerialNumber, error) {
	// Create a temp certificate to determine the public part of the issuing CA
	cert, err := issue("localhost", decade)
	if err != nil {
		return nil, "", err
	}

	issuingCA := cert.GetIssuingCA()

	// We are not going to need this certificate - remove it
	cm.ReleaseCertificate(cert.GetCommonName())

	return issuingCA, cert.GetSerialNumber(), err
}

func (cm *CertManager) IssueCertificate(cn certificate.CommonName, validityPeriod time.Duration) (*certificate.Certificate, error) {
	secret, err := cm.client.Logical().Write(getIssueURL(cm.role).String(), getIssuanceData(cn, validityPeriod))
	if err != nil {
		// TODO(#3962): metric might not be scraped before process restart resulting from this error
		log.Error().Err(err).Str(errcode.Kind, errcode.GetErrCodeWithMetric(errcode.ErrIssuingCert)).
			Msgf("Error issuing new certificate for CN=%s", cn)
		return nil, err
	}

	return &certificate.Certificate{
		CommonName:   cn,
		SerialNumber: certificate.SerialNumber(secret.Data[serialNumberField].(string)),
		// Expiration:   time.Now() + validityPeriod,
		CertChain:  pem.Certificate(secret.Data[certificateField].(string)),
		PrivateKey: []byte(secret.Data[privateKeyField].(string)),
		IssuingCA:  pem.RootCertificate(secret.Data[issuingCAField].(string)),
	}, nil
}

func (cm *CertManager) deleteFromCache(cn certificate.CommonName) {
	cm.cache.Delete(cn)
}

func (cm *CertManager) getFromCache(cn certificate.CommonName) *certificate.Certificate {
	if certificateInterface, exists := cm.cache.Load(cn); exists {
		cert := certificateInterface.(*certificate.Certificate)
		log.Trace().Msgf("Certificate found in cache SerialNumber=%s", cert.GetSerialNumber())
		if rotor.ShouldRotate(cert) {
			log.Trace().Msgf("Certificate found in cache but has expired SerialNumber=%s", cert.GetSerialNumber())
			return nil
		}
		return cert
	}
	return nil
}
