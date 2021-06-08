package sds

import (
	xds_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	xds_auth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	xds_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	xds_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"

	"github.com/openservicemesh/osm/pkg/catalog"
	"github.com/openservicemesh/osm/pkg/certificate"
	"github.com/openservicemesh/osm/pkg/configurator"
	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/envoy/registry"
	"github.com/openservicemesh/osm/pkg/envoy/secrets"
	"github.com/openservicemesh/osm/pkg/identity"
)

// NewResponse creates a new Secrets Discovery Response.
func NewResponse(meshCatalog catalog.MeshCataloger, proxy *envoy.Proxy, request *xds_discovery.DiscoveryRequest, cfg configurator.Configurator, certManager certificate.Manager, _ *registry.ProxyRegistry) ([]types.Resource, error) {
	log.Info().Msgf("Composing SDS Discovery Response for Envoy with certificate SerialNumber=%s on Pod with UID=%s", proxy.GetCertificateSerialNumber(), proxy.GetPodUID())

	// OSM currently relies on kubernetes ServiceAccount for service identity
	svcAccount, err := envoy.GetServiceAccountFromProxyCertificate(proxy.GetCertificateCommonName())
	if err != nil {
		log.Error().Err(err).Msgf("Error retrieving ServiceAccount for Envoy with certificate SerialNumber=%s on Pod with UID=%s", proxy.GetCertificateSerialNumber(), proxy.GetPodUID())
		return nil, err
	}

	s := &sdsImpl{
		meshCatalog:     meshCatalog,
		certManager:     certManager,
		cfg:             cfg,
		serviceIdentity: svcAccount.ToServiceIdentity(),
	}

	var sdsResources []types.Resource

	// The DiscoveryRequest contains the requested certs
	requestedCerts := request.ResourceNames

	log.Info().Msgf("Creating SDS response for request for ResourceNames (certificates) %v from Envoy with certificate SerialNumber=%s on Pod with UID=%s", requestedCerts, proxy.GetCertificateSerialNumber(), proxy.GetPodUID())

	// 1. Issue a service certificate for this proxy
	cert, err := certManager.IssueCertificate(s.serviceIdentity.GetCertificateCommonName(), cfg.GetServiceCertValidityPeriod())
	if err != nil {
		log.Error().Err(err).Msgf("Error issuing a certificate for proxy with certificate SerialNumber=%s", proxy.GetCertificateSerialNumber())
		return nil, err
	}

	// 2. Create SDS secret resources based on the requested certs in the DiscoveryRequest
	// request.ResourceNames is expected to be a list of either "service-cert:namespace/service" or "root-cert:namespace/service"
	for _, envoyProto := range s.getSDSSecrets(cert, requestedCerts, proxy) {
		sdsResources = append(sdsResources, envoyProto)
	}

	return sdsResources, nil
}

func (s *sdsImpl) getSDSSecrets(cert certificate.Certificater, requestedCerts []string, proxy *envoy.Proxy) (certs []*xds_auth.Secret) {
	// requestedCerts is expected to be a list of either of the following:
	// - "service-cert:namespace/service-account"
	// - "root-cert-for-mtls-outbound:namespace/service"
	// - "root-cert-for-mtls-inbound:namespace/service-service-account"
	// - "root-cert-for-https:namespace/service-service-account"

	// The Envoy makes a request for a list of resources (aka certificates), which we will send as a response to the SDS request.
	for _, requestedCertificate := range requestedCerts {
		sdsCert, err := secrets.UnmarshalSDSCert(requestedCertificate)
		if err != nil {
			log.Error().Err(err).Msgf("Invalid resource kind requested: %q", requestedCertificate)
			continue
		}

		log.Debug().Msgf("Envoy with certificate SerialNumber=%s on Pod with UID=%s requested %s", proxy.GetCertificateSerialNumber(), proxy.GetPodUID(), requestedCertificate)

		switch sdsCert.CertType {
		// A service certificate is requested
		case secrets.ServiceCertType:
			envoySecret, err := getServiceCertSecret(cert, requestedCertificate)
			if err != nil {
				log.Error().Err(err).Msgf("Error creating cert %s for Envoy with xDS Certificate SerialNumber=%s on Pod with UID=%s",
					requestedCertificate, proxy.GetCertificateSerialNumber(), proxy.GetPodUID())
				continue
			}
			certs = append(certs, envoySecret)

		// A root certificate used to validate a service certificate is requested
		case secrets.RootCertTypeForMTLSInbound, secrets.RootCertTypeForMTLSOutbound, secrets.RootCertTypeForHTTPS:
			envoySecret, err := s.getRootCert(cert, *sdsCert)
			if err != nil {
				log.Error().Err(err).Msgf("Error creating cert %s for Envoy with xDS Certificate SerialNumber=%s on Pod with UID=%s",
					requestedCertificate, proxy.GetCertificateSerialNumber(), proxy.GetPodUID())
				continue
			}
			certs = append(certs, envoySecret)
		}
	}

	return certs
}

// getServiceCertSecret creates the struct with certificates for the service, which the
// connected Envoy proxy belongs to.
func getServiceCertSecret(cert certificate.Certificater, name string) (*xds_auth.Secret, error) {
	secret := &xds_auth.Secret{
		// The Name field must match the tls_context.common_tls_context.tls_certificate_sds_secret_configs.name in the Envoy yaml config
		Name: name,
		Type: &xds_auth.Secret_TlsCertificate{
			TlsCertificate: &xds_auth.TlsCertificate{
				CertificateChain: &xds_core.DataSource{
					Specifier: &xds_core.DataSource_InlineBytes{
						InlineBytes: cert.GetCertificateChain(),
					},
				},
				PrivateKey: &xds_core.DataSource{
					Specifier: &xds_core.DataSource_InlineBytes{
						InlineBytes: cert.GetPrivateKey(),
					},
				},
			},
		},
	}
	return secret, nil
}

func (s *sdsImpl) getRootCert(cert certificate.Certificater, sdscert secrets.SDSCert) (*xds_auth.Secret, error) {
	secret := &xds_auth.Secret{
		// The Name field must match the tls_context.common_tls_context.tls_certificate_sds_secret_configs.name
		Name: sdscert.String(),
		Type: &xds_auth.Secret_ValidationContext{
			ValidationContext: &xds_auth.CertificateValidationContext{
				TrustedCa: &xds_core.DataSource{
					Specifier: &xds_core.DataSource_InlineBytes{
						InlineBytes: cert.GetIssuingCA(),
					},
				},
			},
		},
	}

	if s.cfg.IsPermissiveTrafficPolicyMode() {
		// In permissive mode, there are no SMI TrafficTarget policies, so
		// SAN matching is not required.
		return secret, nil
	}

	svcIdentitiesInCertRequest, err := getServiceIdentitiesFromCert(sdscert, s.serviceIdentity, s.meshCatalog)
	if err != nil {
		return nil, err
	}

	secret.GetValidationContext().MatchSubjectAltNames = getSubjectAltNamesFromSvcIdentities(svcIdentitiesInCertRequest)
	return secret, nil
}

// Given a requested SDS Cert, this function returns the Service Identities, which match that SDS Cert
// Example: given "service-cert:namespace/service-account", this will return ServiceIdentity("namespace.service-account.cluster.local")
func getServiceIdentitiesFromCert(sdscert secrets.SDSCert, serviceIdentity identity.ServiceIdentity, meshCatalog catalog.MeshCataloger) ([]identity.ServiceIdentity, error) {
	// Program SAN matching based on SMI TrafficTarget policies
	switch sdscert.CertType {
	case secrets.RootCertTypeForMTLSOutbound:
		// For the outbound certificate validation context, the SANs needs to match the list of service identities
		// corresponding to the upstream service. This means, if the sdscert.Name points to service 'X',
		// the SANs for this certificate should correspond to the service identities of 'X'.
		svcIdentity, err := sdscert.GetSvcIdentity()
		if err != nil {
			log.Error().Err(err).Msgf("Error unmarshalling upstream service for outbound cert %s", sdscert)
			return nil, err
		}
		return []identity.ServiceIdentity{*svcIdentity}, nil

	case secrets.RootCertTypeForMTLSInbound:
		// Verify that the SDS cert request corresponding to the mTLS root validation cert matches the identity
		// of this proxy. If it doesn't, then something is wrong in the system.
		svcAccountInRequest, err := sdscert.GetK8sServiceAccount()
		if err != nil {
			log.Error().Err(err).Msgf("Error unmarshalling service account for inbound mTLS validation cert %s", sdscert)
			return nil, err
		}

		if svcAccountInRequest.ToServiceIdentity() != serviceIdentity {
			log.Error().Err(errCertMismatch).Msgf("Request for SDS cert %s does not belong to proxy with identity %s", sdscert.Name, serviceIdentity)
			return nil, errCertMismatch
		}

		// For the inbound certificate validation context, the SAN needs to match the list of all downstream
		// service identities that are allowed to connect to this upstream identity. This means, if the upstream proxy
		// identity is 'X', the SANs for this certificate should correspond to all the downstream identities
		// allowed to access 'X'.
		svcIdentities, err := meshCatalog.ListAllowedInboundServiceIdentities(serviceIdentity)
		if err != nil {
			log.Error().Err(err).Msgf("Error listing inbound service accounts for proxy with ServiceAccount %s", serviceIdentity)
			return nil, err
		}
		return svcIdentities, nil

	default:
		log.Debug().Msgf("SAN matching not needed for cert %s", sdscert)
	}

	return nil, nil
}

// Note: ServiceIdentity must be in the format "name.namespace" [https://github.com/openservicemesh/osm/issues/3188]
func getSubjectAltNamesFromSvcIdentities(serviceIdentities []identity.ServiceIdentity) []*xds_matcher.StringMatcher {
	var matchSANs []*xds_matcher.StringMatcher

	for _, si := range serviceIdentities {
		match := xds_matcher.StringMatcher{
			MatchPattern: &xds_matcher.StringMatcher_Exact{
				Exact: si.String(),
			},
		}
		matchSANs = append(matchSANs, &match)
	}

	return matchSANs
}
