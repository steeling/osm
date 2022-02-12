package certmanager

import (
	"errors"
	"time"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmversionedclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"

	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/messaging"
)

// Options is a type that specifies 'cert-manager.io' certificate provider options
type Options struct {
	IssuerName  string
	IssuerKind  string
	IssuerGroup string

	ca                          certificate.Certificater
	client                      cmversionedclient.Interface
	namespace                   string
	issuerRef                   cmmeta.ObjectReference
	ServiceCertValidityDuration time.Duration
	KeySize                     int
	MsgBroker                   *messaging.Broker
	// msgBroker *messaging.Broker
}

// ValidateCertManagerOptions validates the options for cert-manager.io certificate provider
func (o Options) Validate() error {
	if o.IssuerName == "" {
		return errors.New("IssuerName not specified in cert-manager.io options")
	}

	if o.IssuerKind == "" {
		return errors.New("IssuerKind not specified in cert-manager.io options")
	}

	if o.IssuerGroup == "" {
		return errors.New("IssuerGroup not specified in cert-manager.io options")
	}

	return nil
}
