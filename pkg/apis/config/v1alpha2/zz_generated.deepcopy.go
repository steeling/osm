//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha2

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertManagerProviderSpec) DeepCopyInto(out *CertManagerProviderSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertManagerProviderSpec.
func (in *CertManagerProviderSpec) DeepCopy() *CertManagerProviderSpec {
	if in == nil {
		return nil
	}
	out := new(CertManagerProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CertificateSpec) DeepCopyInto(out *CertificateSpec) {
	*out = *in
	if in.IngressGateway != nil {
		in, out := &in.IngressGateway, &out.IngressGateway
		*out = new(IngressGatewayCertSpec)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CertificateSpec.
func (in *CertificateSpec) DeepCopy() *CertificateSpec {
	if in == nil {
		return nil
	}
	out := new(CertificateSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExtensionService) DeepCopyInto(out *ExtensionService) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExtensionService.
func (in *ExtensionService) DeepCopy() *ExtensionService {
	if in == nil {
		return nil
	}
	out := new(ExtensionService)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ExtensionService) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExtensionServiceList) DeepCopyInto(out *ExtensionServiceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]ExtensionService, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExtensionServiceList.
func (in *ExtensionServiceList) DeepCopy() *ExtensionServiceList {
	if in == nil {
		return nil
	}
	out := new(ExtensionServiceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *ExtensionServiceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExtensionServiceSpec) DeepCopyInto(out *ExtensionServiceSpec) {
	*out = *in
	if in.ConnectTimeout != nil {
		in, out := &in.ConnectTimeout, &out.ConnectTimeout
		*out = new(v1.Duration)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExtensionServiceSpec.
func (in *ExtensionServiceSpec) DeepCopy() *ExtensionServiceSpec {
	if in == nil {
		return nil
	}
	out := new(ExtensionServiceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExternalAuthzSpec) DeepCopyInto(out *ExternalAuthzSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExternalAuthzSpec.
func (in *ExternalAuthzSpec) DeepCopy() *ExternalAuthzSpec {
	if in == nil {
		return nil
	}
	out := new(ExternalAuthzSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FeatureFlags) DeepCopyInto(out *FeatureFlags) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FeatureFlags.
func (in *FeatureFlags) DeepCopy() *FeatureFlags {
	if in == nil {
		return nil
	}
	out := new(FeatureFlags)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IngressGatewayCertSpec) DeepCopyInto(out *IngressGatewayCertSpec) {
	*out = *in
	if in.SubjectAltNames != nil {
		in, out := &in.SubjectAltNames, &out.SubjectAltNames
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	out.Secret = in.Secret
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IngressGatewayCertSpec.
func (in *IngressGatewayCertSpec) DeepCopy() *IngressGatewayCertSpec {
	if in == nil {
		return nil
	}
	out := new(IngressGatewayCertSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshConfig) DeepCopyInto(out *MeshConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshConfig.
func (in *MeshConfig) DeepCopy() *MeshConfig {
	if in == nil {
		return nil
	}
	out := new(MeshConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshConfigList) DeepCopyInto(out *MeshConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]MeshConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshConfigList.
func (in *MeshConfigList) DeepCopy() *MeshConfigList {
	if in == nil {
		return nil
	}
	out := new(MeshConfigList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshConfigList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshConfigSpec) DeepCopyInto(out *MeshConfigSpec) {
	*out = *in
	in.Sidecar.DeepCopyInto(&out.Sidecar)
	in.Traffic.DeepCopyInto(&out.Traffic)
	out.Observability = in.Observability
	in.Certificate.DeepCopyInto(&out.Certificate)
	out.FeatureFlags = in.FeatureFlags
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshConfigSpec.
func (in *MeshConfigSpec) DeepCopy() *MeshConfigSpec {
	if in == nil {
		return nil
	}
	out := new(MeshConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshRootCertificate) DeepCopyInto(out *MeshRootCertificate) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshRootCertificate.
func (in *MeshRootCertificate) DeepCopy() *MeshRootCertificate {
	if in == nil {
		return nil
	}
	out := new(MeshRootCertificate)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshRootCertificate) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshRootCertificateComponentStatuses) DeepCopyInto(out *MeshRootCertificateComponentStatuses) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshRootCertificateComponentStatuses.
func (in *MeshRootCertificateComponentStatuses) DeepCopy() *MeshRootCertificateComponentStatuses {
	if in == nil {
		return nil
	}
	out := new(MeshRootCertificateComponentStatuses)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshRootCertificateCondition) DeepCopyInto(out *MeshRootCertificateCondition) {
	*out = *in
	in.LastTransitionTime.DeepCopyInto(&out.LastTransitionTime)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshRootCertificateCondition.
func (in *MeshRootCertificateCondition) DeepCopy() *MeshRootCertificateCondition {
	if in == nil {
		return nil
	}
	out := new(MeshRootCertificateCondition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshRootCertificateList) DeepCopyInto(out *MeshRootCertificateList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]MeshRootCertificate, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshRootCertificateList.
func (in *MeshRootCertificateList) DeepCopy() *MeshRootCertificateList {
	if in == nil {
		return nil
	}
	out := new(MeshRootCertificateList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *MeshRootCertificateList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshRootCertificateSpec) DeepCopyInto(out *MeshRootCertificateSpec) {
	*out = *in
	in.Provider.DeepCopyInto(&out.Provider)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshRootCertificateSpec.
func (in *MeshRootCertificateSpec) DeepCopy() *MeshRootCertificateSpec {
	if in == nil {
		return nil
	}
	out := new(MeshRootCertificateSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MeshRootCertificateStatus) DeepCopyInto(out *MeshRootCertificateStatus) {
	*out = *in
	if in.TransitionAfter != nil {
		in, out := &in.TransitionAfter, &out.TransitionAfter
		*out = (*in).DeepCopy()
	}
	out.ComponentStatuses = in.ComponentStatuses
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]MeshRootCertificateCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MeshRootCertificateStatus.
func (in *MeshRootCertificateStatus) DeepCopy() *MeshRootCertificateStatus {
	if in == nil {
		return nil
	}
	out := new(MeshRootCertificateStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ObservabilitySpec) DeepCopyInto(out *ObservabilitySpec) {
	*out = *in
	out.Tracing = in.Tracing
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ObservabilitySpec.
func (in *ObservabilitySpec) DeepCopy() *ObservabilitySpec {
	if in == nil {
		return nil
	}
	out := new(ObservabilitySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ProviderSpec) DeepCopyInto(out *ProviderSpec) {
	*out = *in
	if in.CertManager != nil {
		in, out := &in.CertManager, &out.CertManager
		*out = new(CertManagerProviderSpec)
		**out = **in
	}
	if in.Vault != nil {
		in, out := &in.Vault, &out.Vault
		*out = new(VaultProviderSpec)
		**out = **in
	}
	if in.Tresor != nil {
		in, out := &in.Tresor, &out.Tresor
		*out = new(TresorProviderSpec)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProviderSpec.
func (in *ProviderSpec) DeepCopy() *ProviderSpec {
	if in == nil {
		return nil
	}
	out := new(ProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretKeyReferenceSpec) DeepCopyInto(out *SecretKeyReferenceSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretKeyReferenceSpec.
func (in *SecretKeyReferenceSpec) DeepCopy() *SecretKeyReferenceSpec {
	if in == nil {
		return nil
	}
	out := new(SecretKeyReferenceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SidecarSpec) DeepCopyInto(out *SidecarSpec) {
	*out = *in
	in.Resources.DeepCopyInto(&out.Resources)
	if in.CipherSuites != nil {
		in, out := &in.CipherSuites, &out.CipherSuites
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.ECDHCurves != nil {
		in, out := &in.ECDHCurves, &out.ECDHCurves
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SidecarSpec.
func (in *SidecarSpec) DeepCopy() *SidecarSpec {
	if in == nil {
		return nil
	}
	out := new(SidecarSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TracingSpec) DeepCopyInto(out *TracingSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TracingSpec.
func (in *TracingSpec) DeepCopy() *TracingSpec {
	if in == nil {
		return nil
	}
	out := new(TracingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TrafficSpec) DeepCopyInto(out *TrafficSpec) {
	*out = *in
	if in.OutboundIPRangeExclusionList != nil {
		in, out := &in.OutboundIPRangeExclusionList, &out.OutboundIPRangeExclusionList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.OutboundIPRangeInclusionList != nil {
		in, out := &in.OutboundIPRangeInclusionList, &out.OutboundIPRangeInclusionList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.OutboundPortExclusionList != nil {
		in, out := &in.OutboundPortExclusionList, &out.OutboundPortExclusionList
		*out = make([]int, len(*in))
		copy(*out, *in)
	}
	if in.InboundPortExclusionList != nil {
		in, out := &in.InboundPortExclusionList, &out.InboundPortExclusionList
		*out = make([]int, len(*in))
		copy(*out, *in)
	}
	out.InboundExternalAuthorization = in.InboundExternalAuthorization
	if in.NetworkInterfaceExclusionList != nil {
		in, out := &in.NetworkInterfaceExclusionList, &out.NetworkInterfaceExclusionList
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TrafficSpec.
func (in *TrafficSpec) DeepCopy() *TrafficSpec {
	if in == nil {
		return nil
	}
	out := new(TrafficSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TresorCASpec) DeepCopyInto(out *TresorCASpec) {
	*out = *in
	out.SecretRef = in.SecretRef
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TresorCASpec.
func (in *TresorCASpec) DeepCopy() *TresorCASpec {
	if in == nil {
		return nil
	}
	out := new(TresorCASpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TresorProviderSpec) DeepCopyInto(out *TresorProviderSpec) {
	*out = *in
	out.CA = in.CA
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TresorProviderSpec.
func (in *TresorProviderSpec) DeepCopy() *TresorProviderSpec {
	if in == nil {
		return nil
	}
	out := new(TresorProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VaultProviderSpec) DeepCopyInto(out *VaultProviderSpec) {
	*out = *in
	out.Token = in.Token
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VaultProviderSpec.
func (in *VaultProviderSpec) DeepCopy() *VaultProviderSpec {
	if in == nil {
		return nil
	}
	out := new(VaultProviderSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *VaultTokenSpec) DeepCopyInto(out *VaultTokenSpec) {
	*out = *in
	out.SecretKeyRef = in.SecretKeyRef
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new VaultTokenSpec.
func (in *VaultTokenSpec) DeepCopy() *VaultTokenSpec {
	if in == nil {
		return nil
	}
	out := new(VaultTokenSpec)
	in.DeepCopyInto(out)
	return out
}
