package tresor

import (
	"time"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/messaging"
)

// Options is a type that specifies 'Tresor' certificate provider options
type Options struct {
	KeySize                     int
	ServiceCertValidityDuration time.Duration
	MsgBroker                   *messaging.Broker

	ca                       certificate.Certificater
	certificatesOrganization string
}

func (o Options) Validate() error {
	if o.ca == nil {
		return errNoIssuingCA
	}
	return nil
}
