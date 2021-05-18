package webhook

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/rs/zerolog/log"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AdmissionError struct {
	Allowed  bool // sets the Response.Allowed
	Warnings []string
	Err      error
}

func (a *AdmissionError) Is(e error) bool {
	_, ok := e.(*AdmissionError)
	return ok
}

func (a *AdmissionError) Error() string {
	return fmt.Sprintf("request allowed: %t due to error: %s", a.Allowed, a.Err)
}

func (a *AdmissionError) ToResponse() *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: a.Allowed,
		Result: &metav1.Status{
			Message: a.Err.Error(),
		},
		Warnings: a.Warnings,
	}
}

// GetAdmissionRequestBody returns the body of the admission request
func GetAdmissionRequestBody(w http.ResponseWriter, req *http.Request) ([]byte, error) {
	defer req.Body.Close()
	admissionRequestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msgf("Error reading admission request body; Responded to admission request with HTTP %v", http.StatusInternalServerError)
		return admissionRequestBody, err
	}

	if len(admissionRequestBody) == 0 {
		http.Error(w, errEmptyAdmissionRequestBody.Error(), http.StatusBadRequest)
		log.Error().Err(errEmptyAdmissionRequestBody).Msgf("Responded to admission request with HTTP %v", http.StatusBadRequest)

		return nil, errEmptyAdmissionRequestBody
	}

	return admissionRequestBody, nil
}

// // ResponseFromError wraps error as AdmissionResponse
func ResponseFromError(err error) *admissionv1.AdmissionResponse {
	if err == nil {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}
	}
	if a, ok := err.(*AdmissionError); ok {
		return a.ToResponse()
	}
	return &admissionv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
