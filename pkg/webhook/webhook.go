package webhook

import (
	"io/ioutil"
	"net/http"

	"github.com/rs/zerolog/log"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

// // AdmissionError wraps error as AdmissionResponse
func AdmissionError(err error) *admissionv1.AdmissionResponse {
	if err == nil {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}
	}
	return &admissionv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
