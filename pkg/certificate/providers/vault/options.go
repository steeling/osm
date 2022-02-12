package vault

import (
	"fmt"
	"time"

	"github.com/pkg/errors"

	"github.com/openservicemesh/osm/pkg/messaging"
)

// Options is a type that specifies 'Hashicorp Vault' certificate provider options
type Options struct {
	ServiceCertValidityDuration time.Duration

	// 	// kubeClient kubernetes.Interface
	// 	// kubeConfig *rest.Config

	// 	// providerNamespace  string
	// 	// caBundleSecretName string

	MsgBroker     *messaging.Broker
	VaultProtocol string
	VaultHost     string
	VaultToken    string
	VaultRole     string
	VaultPort     int
}

// ValidateVaultOptions validates the options for Hashi Vault certificate provider
func (o Options) Validate() error {
	if o.VaultHost == "" {
		return errors.New("VaultHost not specified in Hashi Vault options")
	}

	if o.VaultToken == "" {
		return errors.New("VaultToken not specified in Hashi Vault options")
	}

	if o.VaultRole == "" {
		return errors.New("VaultRole not specified in Hashi Vault options")
	}

	if _, ok := map[string]interface{}{"http": nil, "https": nil}[o.VaultProtocol]; !ok {
		return errors.Errorf("VaultProtocol in Hashi Vault options must be one of [http, https], got %s", o.VaultProtocol)
	}

	return nil
}

func (o Options) Address() string {
	return fmt.Sprintf("%s://%s:%d", o.VaultProtocol, o.VaultHost, o.VaultPort)
}
