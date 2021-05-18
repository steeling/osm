// Package webhook implements utility routines related to Kubernetes' admission webhooks.
package webhook

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
	admissionv1 "k8s.io/api/admission/v1"
)

var (
	defaultValidators = map[string]Validator{}
)

// RegisterValidator registers all validators. It is not thread safe.
// It assumes one validator per GVK. If multiple validations need to happen it should all happen in the single validator
func RegisterValidator(gvk string, v Validator) error {
	if _, ok := defaultValidators[gvk]; ok {
		return fmt.Errorf("%s is already registered", gvk)
	}
	defaultValidators[gvk] = v
	return nil
}

/* 	Validator is a function that accepts an AdmissionRequest and returns an AdmissionResponse.
There are a few ways to utilize the Validator function:

1. return resp, nil

	In this case we simply return the raw resp. This allows for the most customization.

2. return nil, err

	In this case we convert the error to an AdmissionResponse.  If the error type is an ResponseFromError, we
	convert accordingly, which allows for some customization of the AdmissionResponse. Otherwise, we set Allow to
	false and the status to the error message.

3. return nil, nil

	In this case we create a simple AdmissionResponse, with Allow set to true.

4. Note that resp, err will ignore the error. It assumes that you are returning nil for resp if there is an error

In all of the above cases we always populate the UID of the response from the request.

An example of a validator:

func FakeValidator(req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error) {
	o, n := &FakeObj{}, &FakeObj{}
	// If you need to compare against the old object
	if err := json.NewDecoder(bytes.NewBuffer(req.OldObject.Raw)).Decode(o); err != nil {
		returrn nil, err
	}

	if err := json.NewDecoder(bytes.NewBuffer(req.OldObject.Raw)).Decode(n); err != nil {
		returrn nil, err
	}

	// validate the objects, potentially returning an error, or a more detailed AdmissionResponse.

	// This will set allow to true
	return nil, nil
}
*/
type Validator func(req *admissionv1.AdmissionRequest) (*admissionv1.AdmissionResponse, error)

type ValidatingWebhookServer struct {
	// Map of Resource (GroupVersionKind), to validator
	Validators map[string]Validator
}

// New returns a ValidatingWebhookServer with the defaultValidators that were previously registered.
func New() *ValidatingWebhookServer {
	return &ValidatingWebhookServer{
		Validators: defaultValidators,
	}
}

// GetAdmissionRequestBody returns the body of the admission request
func (s *ValidatingWebhookServer) HandleValidation(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	adReq := new(admissionv1.AdmissionRequest)
	if err := json.NewDecoder(req.Body).Decode(adReq); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msgf("Error reading admission request body; Responded to admission request with HTTP %v", http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(s.handleValidation(adReq))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msgf("Error marshaling admission response body; Responded to admission request with HTTP %v", http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msgf("Truncated response; error writing output to http writer; Responsed to admission request with HTTP %v", http.StatusInternalServerError)
		return
	}
}

func (s *ValidatingWebhookServer) handleValidation(req *admissionv1.AdmissionRequest) (resp *admissionv1.AdmissionResponse) {
	var err error
	defer func() {
		resp.UID = req.UID // ensure this is always set
	}()
	gvk := req.Kind.String()
	v, ok := s.Validators[gvk]
	if !ok {
		return ResponseFromError(fmt.Errorf("unknown gvk: %s", gvk))
	}

	// We don't explicitly do an if err != nil, since we will set it from
	resp, err = v(req)
	if resp != nil && err != nil {
		log.Warn().Msgf("Warning! validator for gvk: %s returned both an AdmissionResponse *and* an error. Please return one or the other", gvk)
	}
	if resp == nil {
		resp = ResponseFromError(err)
	}
	// Ensure this is copied over.
	return resp
}
