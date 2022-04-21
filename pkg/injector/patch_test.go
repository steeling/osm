package injector

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	mapset "github.com/deckarep/golang-set"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	tassert "github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	configv1alpha2 "github.com/openservicemesh/osm/pkg/apis/config/v1alpha2"

	"github.com/openservicemesh/osm/pkg/certificate/providers/tresor"
	"github.com/openservicemesh/osm/pkg/configurator"
	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/k8s"
	"github.com/openservicemesh/osm/pkg/tests"
)

const (
	namespace  = "-namespace-"
	podName    = "-pod-name-"
	envoyImage = "-envoy-image-"
)

func TestCreatePatch(t *testing.T) {
	// Setup all variables and constants needed for the tests
	proxyUUID := uuid.New()

	testCases := []struct {
		name            string
		os              string
		namespace       *corev1.Namespace
		dryRun          bool
		expectedPatches []string
	}{
		{
			name: "creates a patch for a unix worker",
			os:   constants.OSLinux,
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			},
			expectedPatches: []string{
				// Add Envoy UID Label
				`"path":"/metadata/labels"`,
				fmt.Sprintf(`"value":{"osm-proxy-uuid":"%v"`, proxyUUID),
				// Add Volumes
				`"path":"/spec/volumes"`,
				fmt.Sprintf(`"value":[{"name":"envoy-bootstrap-config-volume","secret":{"secretName":"envoy-bootstrap-config-%v"}}]}`, proxyUUID),
				// Add Init Container
				`"path":"/spec/initContainers"`,
				`"command":["/bin/sh"]`,
				// Add Envoy Container
				`"path":"/spec/containers"`,
				`"command":["envoy"]`,
			},
		},
		{
			name: "creates a patch for a windows worker",
			os:   constants.OSWindows,
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			},
			expectedPatches: []string{
				// Add Envoy UID Label
				`"path":"/metadata/labels"`,
				fmt.Sprintf(`"value":{"osm-proxy-uuid":"%v"`, proxyUUID),
				// Add Volumes
				`"path":"/spec/volumes"`,
				fmt.Sprintf(`"value":[{"name":"envoy-bootstrap-config-volume","secret":{"secretName":"envoy-bootstrap-config-%v"}}]}`, proxyUUID),
				// Add Envoy Container
				`"path":"/spec/containers"`,
				`"command":["envoy"]`,
			},
		},
		{
			name: "metrics enabled",
			os:   constants.OSLinux,
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:        namespace,
					Annotations: map[string]string{constants.MetricsAnnotation: "enabled"},
				},
			},
			expectedPatches: []string{
				// Add Envoy UID Label
				`"path":"/metadata/labels"`,
				fmt.Sprintf(`"value":{"osm-proxy-uuid":"%v"`, proxyUUID),
				// Add metrics Annotations
				`"path":"/metadata/annotations"`,
				`"value":{"prometheus.io/path":"/stats/prometheus","prometheus.io/port":"15010","prometheus.io/scrape":"true"}`,
				// Add Volumes
				`"path":"/spec/volumes"`,
				fmt.Sprintf(`"value":[{"name":"envoy-bootstrap-config-volume","secret":{"secretName":"envoy-bootstrap-config-%v"}}]}`, proxyUUID),
				// Add Init Container
				`"path":"/spec/initContainers"`,
				`"command":["/bin/sh"]`,
				// Add Envoy Container
				`"path":"/spec/containers"`,
				`"command":["envoy"]`,
			},
		},
		{
			name: "unix dry run",
			os:   constants.OSLinux,
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			},
			dryRun: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert := tassert.New(t)

			client := fake.NewSimpleClientset()
			mockCtrl := gomock.NewController(t)
			mockNsController := k8s.NewMockController(mockCtrl)
			mockNsController.EXPECT().GetNamespace(namespace).Return(tc.namespace)
			_, err := client.CoreV1().Namespaces().Create(context.TODO(), tc.namespace, metav1.CreateOptions{})
			assert.NoError(err)

			wh := &mutatingWebhook{
				kubeClient:          client,
				kubeController:      mockNsController,
				certManager:         tresor.NewFake(nil),
				configurator:        setupMockConfigurator(mockCtrl, tc.os == constants.OSLinux),
				nonInjectNamespaces: mapset.NewSet(),
			}

			pod := tests.NewOsSpecificPodFixture(namespace, podName, tests.BookstoreServiceAccountName, nil, tc.os)

			raw, err := json.Marshal(pod)
			assert.NoError(err)

			req := &admissionv1.AdmissionRequest{
				Namespace: namespace,
				Object:    runtime.RawExtension{Raw: raw},
				DryRun:    &tc.dryRun,
			}
			rawPatches, err := wh.createPatch(&pod, req, proxyUUID)

			assert.NoError(err)

			patches := string(rawPatches)

			for _, expectedPatch := range tc.expectedPatches {
				assert.Contains(patches, expectedPatch)
			}
		})
	}

	t.Run("error checking if metrics is enabled", func(t *testing.T) {
		assert := tassert.New(t)
		client := fake.NewSimpleClientset()
		mockCtrl := gomock.NewController(t)
		mockConfigurator := configurator.NewMockConfigurator(mockCtrl)
		mockNsController := k8s.NewMockController(mockCtrl)

		wh := &mutatingWebhook{
			kubeClient:          client,
			kubeController:      mockNsController,
			certManager:         tresor.NewFake(nil),
			configurator:        mockConfigurator,
			nonInjectNamespaces: mapset.NewSet(),
		}

		mockConfigurator.EXPECT().GetEnvoyImage().Return("")
		mockConfigurator.EXPECT().GetMeshConfig().AnyTimes()

		pod := tests.NewOsSpecificPodFixture(namespace, podName, tests.BookstoreServiceAccountName, nil, constants.OSLinux)

		raw, err := json.Marshal(pod)
		assert.NoError(err)

		req := &admissionv1.AdmissionRequest{
			Namespace: "not-" + namespace,
			Object:    runtime.RawExtension{Raw: raw},
		}
		_, err = wh.createPatch(&pod, req, proxyUUID)
		assert.Error(err)
	})
}

func setupMockConfigurator(mockCtrl *gomock.Controller, linux bool) *configurator.MockConfigurator {
	mockConfigurator := configurator.NewMockConfigurator(mockCtrl)

	mockConfigurator.EXPECT().GetEnvoyWindowsImage().Return("envoy-linux-image").AnyTimes()
	mockConfigurator.EXPECT().GetEnvoyImage().Return("envoy-windows-image").AnyTimes()
	mockConfigurator.EXPECT().GetInitContainerImage().Return("init-container-image").AnyTimes()

	if linux {
		mockConfigurator.EXPECT().IsPrivilegedInitContainer().Return(false).Times(1)
	}

	mockConfigurator.EXPECT().GetMeshConfig().Return(configv1alpha2.MeshConfig{}).AnyTimes()
	mockConfigurator.EXPECT().GetEnvoyLogLevel().Return("").Times(1)
	mockConfigurator.EXPECT().GetProxyResources().Return(corev1.ResourceRequirements{}).AnyTimes()
	mockConfigurator.EXPECT().GetCertKeyBitSize().Return(2048).AnyTimes()
	return mockConfigurator
}

func TestVerifyPrerequisites(t *testing.T) {
	testCases := []struct {
		name         string
		podOS        string
		linuxImage   string
		windowsImage string
		initImage    string
		expectErr    bool
	}{
		{
			name:       "prereqs met for linux pod",
			linuxImage: "envoy",
			initImage:  "init",
			expectErr:  false,
		},
		{
			name:       "prereqs not met for linux pod when init container image is missing",
			linuxImage: "envoy",
			expectErr:  true,
		},
		{
			name:      "prereqs not met for linux pod when envoy container image is missing",
			initImage: "init",
			expectErr: true,
		},
		{
			name:         "prereqs met for windows pod",
			podOS:        "windows",
			windowsImage: "windows",
			initImage:    "init",
			expectErr:    false,
		},
		{
			name:         "prereqs met for windows pod when init container image is missing",
			podOS:        "windows",
			windowsImage: "envoy",
			expectErr:    false,
		},
		{
			name:      "prereqs not met for windows pod when envoy container image is missing",
			initImage: "init",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			assert := tassert.New(t)
			mockCfg := configurator.NewMockConfigurator(mockCtrl)

			wh := &mutatingWebhook{
				configurator: mockCfg,
			}

			mockCfg.EXPECT().GetEnvoyImage().Return(tc.linuxImage).AnyTimes()
			mockCfg.EXPECT().GetEnvoyWindowsImage().Return(tc.windowsImage).AnyTimes()
			mockCfg.EXPECT().GetInitContainerImage().Return(tc.initImage).AnyTimes()

			err := wh.verifyPrerequisites(tc.podOS)
			assert.Equal(tc.expectErr, err != nil)
		})
	}
}

func TestMaybeStripOSMConfiguration(t *testing.T) {
	// tests, nothing on it
	// 4. has it not in the first spot, removed.
	original := tests.NewPodFixture(namespace, podName, tests.BookstoreServiceAccountName, nil)

	original.Spec.Containers = []corev1.Container{
		{
			Name: "test-container",
		},
	}

	original.Spec.Volumes = []corev1.Volume{
		{
			Name: "test-volume",
		},
	}

	client := fake.NewSimpleClientset()
	mockCtrl := gomock.NewController(t)

	mockNsController := k8s.NewMockController(mockCtrl)
	mockNsController.EXPECT().GetNamespace("").Return(&corev1.Namespace{}).AnyTimes()
	_, err := client.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{}, metav1.CreateOptions{})
	assert.NoError(t, err)

	wh := &mutatingWebhook{
		kubeClient:          client,
		kubeController:      mockNsController,
		certManager:         tresor.NewFake(nil),
		configurator:        setupMockConfigurator(mockCtrl, true),
		nonInjectNamespaces: mapset.NewSet(),
	}

	// pod := tests.NewOsSpecificPodFixture(namespace, podName, tests.BookstoreServiceAccountName, nil)

	// Create patch should mutate this
	mutated := original.DeepCopy()
	_, err = wh.createPatch(mutated, &admissionv1.AdmissionRequest{}, uuid.New())
	assert.NoError(t, err)
	// verify it got mutated
	tassert.Contains(t, mutated.Labels, constants.EnvoyUniqueIDLabelName)

	irregular := mutated.DeepCopy()

	irregular.Spec.Volumes = append(irregular.Spec.Volumes, corev1.Volume{Name: "test-volume-2"})
	irregular.Spec.InitContainers = append(irregular.Spec.InitContainers, corev1.Container{Name: "test-init-2"})
	irregular.Spec.Containers = append(irregular.Spec.Containers, corev1.Container{Name: "test-container-2"})

	testCases := []struct {
		name     string
		input    corev1.Pod
		expected corev1.Pod
	}{
		{
			name:     "pod that has not been injected, doesn't change",
			input:    original,
			expected: *original.DeepCopy(),
		},
		{
			name:     "pod that has been injected, has all the osm components removed ",
			input:    *mutated,
			expected: *original.DeepCopy(),
		},
		{
			name:     "pod with volumes or sidecar in different locations still has the correct components removed",
			input:    *irregular,
			expected: *original.DeepCopy(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fmt.Println("here's the deepcopy:", original.DeepCopy())
			err := wh.maybeStripOSMConfiguration(&tc.input, "")
			tassert.NoError(t, err)
			tassert.Equal(t, tc.expected, tc.input)
		})
	}
}
