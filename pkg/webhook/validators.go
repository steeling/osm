package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	cv1alpha1 "github.com/openservicemesh/osm/pkg/apis/config/v1alpha1"
	pv1alpha1 "github.com/openservicemesh/osm/pkg/apis/policy/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	gvk := metav1.GroupVersionKind{
		Kind:    "Egress",
		Group:   "policy.osm.io",
		Version: "v1alpha1",
	}
	RegisterValidator(gvk.String(), EgressValidator)
}

func EgressValidator(req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
	egress := &pv1alpha1.Egress{}
	if err := json.NewDecoder(bytes.NewBuffer(req.Object.Raw)).Decode(egress); err != nil {
		return nil, err
	}

	for _, m := range egress.Spec.Matches {
		if m.Kind != "HTTPRouteGroup" {
			return nil, fmt.Errorf("Egress spec matches kind is %s when it should be HTTPRouteGroup", m.Kind)
		}

		if *m.APIGroup != "specs.smi-spec.io/v1alpha4" {
			return nil, fmt.Errorf("Egress spec matches APIGroup is %s when it should be specs.smi-spec.io/v1alpha4", *m.APIGroup)
		}
	}

	return nil, nil
}

func DurationValidator(req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
	config := &cv1alpha1.MeshConfig{}
	if err := json.NewDecoder(bytes.NewBuffer(req.Object.Raw)).Decode(config); err != nil {
		return nil, err
	}

	d, err := time.ParseDuration(config.Spec.Certificate.ServiceCertValidityDuration)
	if err != nil {
		return nil, fmt.Errorf("ServiceCertValidityDuration %s is not valid", d)
	}

	return nil, nil
}
