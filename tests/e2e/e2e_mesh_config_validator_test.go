package e2e

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	config "github.com/openservicemesh/osm/pkg/apis/config/v1alpha1"
	. "github.com/openservicemesh/osm/tests/framework"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testMeshName = "meshconfigtest"
)

var _ = OSMDescribe("Test Submit Mesh Config Policy",
	OSMDescribeInfo{
		Tier:   2,
		Bucket: 5,
	},

	func() {
		Context("MeshConfigValidator", func() {
			It("Tests a valid Mesh Config Policy", func() {
				ctx := context.TODO()
				meshIn := new(config.MeshConfig)
				meshClient := Td.ConfigClient
				meshIn.Name = testMeshName
				//do simplest test with just name added
				meshRet, err := meshClient.ConfigV1alpha1().MeshConfigs(Td.OsmNamespace).Create(ctx, meshIn, v1.CreateOptions{})
				Expect(meshRet).ShouldNot(BeNil())
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})
