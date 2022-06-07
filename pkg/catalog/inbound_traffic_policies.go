package catalog

import (
	"fmt"

	mapset "github.com/deckarep/golang-set"
	access "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/access/v1alpha3"

	"github.com/openservicemesh/osm/pkg/constants"
	"github.com/openservicemesh/osm/pkg/identity"
	"github.com/openservicemesh/osm/pkg/k8s"
	"github.com/openservicemesh/osm/pkg/service"
	"github.com/openservicemesh/osm/pkg/smi"
	"github.com/openservicemesh/osm/pkg/trafficpolicy"
)

const (
	// AllowPartialHostnamesMatch is used to allow a partial/subset match on hostnames in traffic policies
	AllowPartialHostnamesMatch bool = true

	// DisallowPartialHostnamesMatch is used to disallow a partial/subset match on hostnames in traffic policies
	DisallowPartialHostnamesMatch bool = false
)

// GetInboundMeshTrafficPolicy returns the inbound mesh traffic policy for the given upstream identity and services
func (mc *MeshCatalog) GetInboundRules(upstreamIdentity identity.ServiceIdentity) []*trafficpolicy.InboundRule {
	destinationFilter := smi.WithTrafficTargetDestination(upstreamIdentity.ToK8sServiceAccount())
	trafficTargets := mc.meshSpec.ListTrafficTargets(destinationFilter)

	// Create a map of maps to speed up lookups.
	routePolicies := make(map[string]map[string]trafficpolicy.HTTPRouteMatch)
	for _, trafficSpecs := range mc.meshSpec.ListHTTPTrafficSpecs() {
		specKey := getTrafficSpecName(smi.HTTPRouteGroupKind, trafficSpecs.Namespace, trafficSpecs.Name)
		routePolicies[specKey] = make(map[string]trafficpolicy.HTTPRouteMatch)
		for _, trafficSpecsMatches := range trafficSpecs.Spec.Matches {
			serviceRoute := trafficpolicy.HTTPRouteMatch{
				Path:          trafficSpecsMatches.PathRegex,
				PathMatchType: trafficpolicy.PathMatchRegex,
				Methods:       trafficSpecsMatches.Methods,
				Headers:       trafficSpecsMatches.Headers,
			}

			// When pathRegex or/and methods are not defined, they will be wildcarded
			if serviceRoute.Path == "" {
				serviceRoute.Path = constants.RegexMatchAll
			}
			if len(serviceRoute.Methods) == 0 {
				serviceRoute.Methods = []string{constants.WildcardHTTPMethod}
			}
			routePolicies[specKey][trafficSpecsMatches.Name] = serviceRoute
		}
	}

	// From each TrafficTarget and HTTPRouteGroup configuration associated with this service, build routes for it.
	var routingRules []*trafficpolicy.InboundRule
	for _, trafficTarget := range trafficTargets {
		rules := getRoutingRulesFromTrafficTarget(trafficTarget, routePolicies)
		// Multiple TrafficTarget objects can reference the same route, in which case such routes
		// need to be merged to create a single route that includes all the downstream client identities
		// this route is authorized for.
		routingRules = trafficpolicy.MergeRules(routingRules, rules)
	}

	return routingRules
}

func getRoutingRulesFromTrafficTarget(trafficTarget *access.TrafficTarget, routePolicies map[string]map[string]trafficpolicy.HTTPRouteMatch) []*trafficpolicy.InboundRule {
	// Compute the allowed downstream service identities for the given TrafficTarget object
	allowedDownstreamIdentities := mapset.NewSet()
	for _, source := range trafficTarget.Spec.Sources {
		allowedDownstreamIdentities.Add(trafficTargetIdentityToSvcAccount(source).ToServiceIdentity())
	}

	var routingRules []*trafficpolicy.InboundRule
	for _, rule := range trafficTarget.Spec.Rules {
		trafficSpecName := getTrafficSpecName(smi.HTTPRouteGroupKind, trafficTarget.Namespace, rule.Name)
		// TODO(steeling): I think there is a bug, where the SMI spec says if no matches are specified, then all should be applied.
		for _, match := range rule.Matches {
			if matchedRoute, exists := routePolicies[trafficSpecName][match]; exists {
				rule := &trafficpolicy.InboundRule{
					HTTPRouteMatch:           matchedRoute,
					AllowedServiceIdentities: allowedDownstreamIdentities,
				}
				routingRules = append(routingRules, rule)
			} else {
				log.Debug().Msgf("No matching trafficpolicy.HTTPRoute found for match name %s in Traffic Spec %s (in namespace %s)", match, trafficSpecName, trafficTarget.Namespace)
			}
		}
	}

	return routingRules
}

func getTrafficSpecName(trafficSpecKind string, trafficSpecNamespace string, trafficSpecName string) string {
	return fmt.Sprintf("%s/%s/%s", trafficSpecKind, trafficSpecNamespace, trafficSpecName)
}

// AllUpstreamServicesIncludeApex returns a list of all upstream services associated with the given list
// of services. An upstream service is associated with another service if it is a backend for an apex/root service
// in a TrafficSplit config. This function returns a list consisting of the given upstream services and all apex
// services associated with each of those services.
func (mc *MeshCatalog) AllUpstreamServicesIncludeApex(upstreamServices []service.MeshService) []service.MeshService {
	svcSet := mapset.NewSet()
	var allServices []service.MeshService

	// Each service could be a backend in a traffic split config. Construct a list
	// of all possible services the given list of services is associated with.
	for _, svc := range upstreamServices {
		if newlyAdded := svcSet.Add(svc); newlyAdded {
			allServices = append(allServices, svc)
		}

		for _, split := range mc.meshSpec.ListTrafficSplits(smi.WithTrafficSplitBackendService(svc)) {
			svcName := k8s.GetServiceFromHostname(mc.kubeController, split.Spec.Service)
			subdomain := k8s.GetSubdomainFromHostname(mc.kubeController, split.Spec.Service)
			apexMeshService := service.MeshService{
				Namespace:  svc.Namespace,
				Name:       svcName,
				Port:       svc.Port,
				TargetPort: svc.TargetPort,
				Protocol:   svc.Protocol,
			}

			if subdomain != "" {
				apexMeshService.Name = fmt.Sprintf("%s.%s", subdomain, svcName)
			}

			if newlyAdded := svcSet.Add(apexMeshService); newlyAdded {
				allServices = append(allServices, apexMeshService)
			}
		}
	}

	return allServices
}
