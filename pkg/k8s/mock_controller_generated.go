// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/openservicemesh/osm/pkg/k8s (interfaces: Controller)

// Package k8s is a generated GoMock package.
package k8s

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	identity "github.com/openservicemesh/osm/pkg/identity"
	service "github.com/openservicemesh/osm/pkg/service"
	v1 "k8s.io/api/core/v1"
)

// MockController is a mock of Controller interface
type MockController struct {
	ctrl     *gomock.Controller
	recorder *MockControllerMockRecorder
}

// MockControllerMockRecorder is the mock recorder for MockController
type MockControllerMockRecorder struct {
	mock *MockController
}

// NewMockController creates a new mock instance
func NewMockController(ctrl *gomock.Controller) *MockController {
	mock := &MockController{ctrl: ctrl}
	mock.recorder = &MockControllerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockController) EXPECT() *MockControllerMockRecorder {
	return m.recorder
}

// GetEndpoints mocks base method
func (m *MockController) GetEndpoints(arg0 service.MeshService) (*v1.Endpoints, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEndpoints", arg0)
	ret0, _ := ret[0].(*v1.Endpoints)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEndpoints indicates an expected call of GetEndpoints
func (mr *MockControllerMockRecorder) GetEndpoints(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEndpoints", reflect.TypeOf((*MockController)(nil).GetEndpoints), arg0)
}

// GetNamespace mocks base method
func (m *MockController) GetNamespace(arg0 string) *v1.Namespace {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNamespace", arg0)
	ret0, _ := ret[0].(*v1.Namespace)
	return ret0
}

// GetNamespace indicates an expected call of GetNamespace
func (mr *MockControllerMockRecorder) GetNamespace(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNamespace", reflect.TypeOf((*MockController)(nil).GetNamespace), arg0)
}

// GetService mocks base method
func (m *MockController) GetService(arg0 service.MeshService) *v1.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetService", arg0)
	ret0, _ := ret[0].(*v1.Service)
	return ret0
}

// GetService indicates an expected call of GetService
func (mr *MockControllerMockRecorder) GetService(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetService", reflect.TypeOf((*MockController)(nil).GetService), arg0)
}

// IsMetricsEnabled mocks base method
func (m *MockController) IsMetricsEnabled(arg0 *v1.Pod) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsMetricsEnabled", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsMetricsEnabled indicates an expected call of IsMetricsEnabled
func (mr *MockControllerMockRecorder) IsMetricsEnabled(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsMetricsEnabled", reflect.TypeOf((*MockController)(nil).IsMetricsEnabled), arg0)
}

// IsMonitoredNamespace mocks base method
func (m *MockController) IsMonitoredNamespace(arg0 string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsMonitoredNamespace", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsMonitoredNamespace indicates an expected call of IsMonitoredNamespace
func (mr *MockControllerMockRecorder) IsMonitoredNamespace(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsMonitoredNamespace", reflect.TypeOf((*MockController)(nil).IsMonitoredNamespace), arg0)
}

// ListMonitoredNamespaces mocks base method
func (m *MockController) ListMonitoredNamespaces() ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListMonitoredNamespaces")
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListMonitoredNamespaces indicates an expected call of ListMonitoredNamespaces
func (mr *MockControllerMockRecorder) ListMonitoredNamespaces() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListMonitoredNamespaces", reflect.TypeOf((*MockController)(nil).ListMonitoredNamespaces))
}

// ListPods mocks base method
func (m *MockController) ListPods() []*v1.Pod {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListPods")
	ret0, _ := ret[0].([]*v1.Pod)
	return ret0
}

// ListPods indicates an expected call of ListPods
func (mr *MockControllerMockRecorder) ListPods() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListPods", reflect.TypeOf((*MockController)(nil).ListPods))
}

// ListServiceAccounts mocks base method
func (m *MockController) ListServiceAccounts() []*v1.ServiceAccount {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListServiceAccounts")
	ret0, _ := ret[0].([]*v1.ServiceAccount)
	return ret0
}

// ListServiceAccounts indicates an expected call of ListServiceAccounts
func (mr *MockControllerMockRecorder) ListServiceAccounts() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListServiceAccounts", reflect.TypeOf((*MockController)(nil).ListServiceAccounts))
}

// ListServiceAccountsForService mocks base method
func (m *MockController) ListServiceAccountsForService(arg0 service.MeshService) ([]identity.K8sServiceAccount, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListServiceAccountsForService", arg0)
	ret0, _ := ret[0].([]identity.K8sServiceAccount)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListServiceAccountsForService indicates an expected call of ListServiceAccountsForService
func (mr *MockControllerMockRecorder) ListServiceAccountsForService(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListServiceAccountsForService", reflect.TypeOf((*MockController)(nil).ListServiceAccountsForService), arg0)
}

// ListServices mocks base method
func (m *MockController) ListServices() []*v1.Service {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListServices")
	ret0, _ := ret[0].([]*v1.Service)
	return ret0
}

// ListServices indicates an expected call of ListServices
func (mr *MockControllerMockRecorder) ListServices() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListServices", reflect.TypeOf((*MockController)(nil).ListServices))
}
