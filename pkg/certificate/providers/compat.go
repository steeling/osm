package providers

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openservicemesh/osm/pkg/apis/config/v1alpha2"
	"github.com/openservicemesh/osm/pkg/configurator"
	"github.com/openservicemesh/osm/pkg/constants"
)

// NewMRCCompatClient returns a new fake client that is backed by the old config settings, and converts them into
// an MRC.
func NewMRCCompatClient(cfg configurator.Configurator, namespace string, options Options) (*MRCCompatClient, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}

	return &MRCCompatClient{
		mrc: &v1alpha2.MeshRootCertificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "legacy-compat",
				Namespace: namespace,
				Annotations: map[string]string{
					constants.MRCVersionAnnotation: "legacy-compat",
				},
			},
			Spec: v1alpha2.MeshRootCertificateSpec{
				Provider: options.AsProviderSpec(),
			},
			// TODO(#4502): Detect if an actual MRC exists, and set the status accordingly.
			Status: v1alpha2.MeshRootCertificateStatus{
				State:         constants.MRCStateActive,
				RotationStage: constants.MRCStageComplete,
			},
		},
	}, nil
}

// List returns the single, pre-generated MRC. It is intended to implement the certificate.MRCClient interface.
func (c *MRCCompatClient) List() ([]*v1alpha2.MeshRootCertificate, error) {
	return []*v1alpha2.MeshRootCertificate{
		c.mrc,
	}, nil
}

// AddEventHandler is a no-op for the legacy client. The previous client could not handle changes, but we need this
// method to implement the certificate.MRCClient interface.
func (c *MRCCompatClient) AddEventHandler(cache.ResourceEventHandler) {}

// provider.Tresor = &v1alpha2.TresorProviderSpec{SecretName: opts.SecretName}
