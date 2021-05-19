package e2e

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	policy "github.com/openservicemesh/osm/pkg/apis/policy/v1alpha1"
	. "github.com/openservicemesh/osm/tests/framework"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	validTestPort      = 6969
	validTestProtocol  = "https"
	validtestKind      = "ServiceAccount"
	validTestName      = "egresstestsourcespec"
	validTestNamespace = "egresstestsourcespec"
)

var _ = OSMDescribe("Test Submit Egress Policy",
	OSMDescribeInfo{
		Tier:   2,
		Bucket: 5,
	},

	func() {
		Context("EgressValidator", func() {
			It("Tests a valid Egress Policy", func() {
				ctx := context.TODO()
				egressIn := new(policy.Egress)
				egressIn.SetName(validTestName)
				egressIn.Spec.Sources = []policy.SourceSpec{{Kind: validtestKind, Name: validTestName, Namespace: validTestName}}
				egressIn.Spec.Ports = []policy.PortSpec{{Number: validTestPort, Protocol: validTestProtocol}}
				ns := Td.OsmNamespace
				Expect(ctx).ShouldNot(BeNil())
				Expect(ns).ShouldNot(BeNil())
				palpha1 := Td.PolicyClient
				derr := palpha1.PolicyV1alpha1().Egresses(Td.OsmNamespace).Delete(ctx, validTestName, v1.DeleteOptions{})
				if derr != nil {
					//don't error because name is not there first test but report
					GinkgoWriter.Write([]byte("Error deleting last test service:\n" + derr.Error()))
				}
				Expect(palpha1).ShouldNot(BeNil())
				egressOut, err := palpha1.PolicyV1alpha1().Egresses(Td.OsmNamespace).Create(ctx, egressIn, v1.CreateOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(egressOut).ShouldNot(BeNil())
			})
		})
	})
