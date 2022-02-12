package tresor

import (
	"errors"
	"time"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/messaging"
)

// Options is a type that specifies 'Tresor' certificate provider options
type Options struct {
	KeySize                     int
	ServiceCertValidityDuration time.Duration
	MsgBroker                   *messaging.Broker

	CA                       certificate.Certificater
	CertificatesOrganization string
}

func (o Options) Validate() error {
	if o.ca == nil {
		return errNoIssuingCA
	}
	if o.CertificatesOrganization == "" {
		return errors.New("CertificatesOrganization not specified in Tresor options")
	}
	return nil
}
