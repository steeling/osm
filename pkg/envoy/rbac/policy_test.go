package rbac

import (
	"fmt"
	"testing"

	tassert "github.com/stretchr/testify/assert"

	xds_rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	xds_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
)

func TestBuild(t *testing.T) {
	testCases := []struct {
		name                  string
		principals            []string
		ports                 []uint32
		applyPermissionsAsAND bool
		expectedPolicy        *xds_rbac.Policy
	}{
		{
			name:       "testing rules for single principal",
			principals: []string{"foo.domain", "bar.domain"},
			ports:      []uint32{80},
			expectedPolicy: &xds_rbac.Policy{
				Principals: []*xds_rbac.Principal{
					{
						Identifier: &xds_rbac.Principal_Authenticated_{
							Authenticated: &xds_rbac.Principal_Authenticated{
								PrincipalName: &xds_matcher.StringMatcher{
									MatchPattern: &xds_matcher.StringMatcher_Exact{
										Exact: "foo.domain",
									},
								},
							},
						},
					},
					{
						Identifier: &xds_rbac.Principal_Authenticated_{
							Authenticated: &xds_rbac.Principal_Authenticated{
								PrincipalName: &xds_matcher.StringMatcher{
									MatchPattern: &xds_matcher.StringMatcher_Exact{
										Exact: "bar.domain",
									},
								},
							},
						},
					},
				},
				Permissions: []*xds_rbac.Permission{
					{
						Rule: &xds_rbac.Permission_DestinationPort{
							DestinationPort: 80,
						},
					},
				},
			},
		},
		{
			name:       "testing rules for single principal",
			principals: []string{"foo.domain"},
			ports:      []uint32{80, 443},
			expectedPolicy: &xds_rbac.Policy{
				Principals: []*xds_rbac.Principal{
					{
						Identifier: &xds_rbac.Principal_Authenticated_{
							Authenticated: &xds_rbac.Principal_Authenticated{
								PrincipalName: &xds_matcher.StringMatcher{
									MatchPattern: &xds_matcher.StringMatcher_Exact{
										Exact: "foo.domain",
									},
								},
							},
						},
					},
				},
				Permissions: []*xds_rbac.Permission{
					{
						Rule: &xds_rbac.Permission_DestinationPort{
							DestinationPort: 80,
						},
					},
					{
						Rule: &xds_rbac.Permission_DestinationPort{
							DestinationPort: 443,
						},
					},
				},
			},
		},
		{
			// Note that AND ports wouldn't make sense, since you can't have 2 ports at once, but we use it to test
			// the logic.
			name:                  "testing rules for AND ports",
			principals:            []string{"foo.domain"},
			ports:                 []uint32{80, 443},
			applyPermissionsAsAND: true,
			expectedPolicy: &xds_rbac.Policy{
				Principals: []*xds_rbac.Principal{
					{
						Identifier: &xds_rbac.Principal_Authenticated_{
							Authenticated: &xds_rbac.Principal_Authenticated{
								PrincipalName: &xds_matcher.StringMatcher{
									MatchPattern: &xds_matcher.StringMatcher_Exact{
										Exact: "foo.domain",
									},
								},
							},
						},
					},
				},
				Permissions: []*xds_rbac.Permission{
					{
						Rule: &xds_rbac.Permission_AndRules{
							AndRules: &xds_rbac.Permission_Set{
								Rules: []*xds_rbac.Permission{
									{
										Rule: &xds_rbac.Permission_DestinationPort{
											DestinationPort: 80,
										},
									},
									{
										Rule: &xds_rbac.Permission_DestinationPort{
											DestinationPort: 443,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:       "testing rule for ANY principal when no ports specified",
			principals: []string{"foo.domain", "*"},
			expectedPolicy: &xds_rbac.Policy{
				Principals: []*xds_rbac.Principal{
					{
						Identifier: &xds_rbac.Principal_Any{Any: true},
					},
				},
				Permissions: []*xds_rbac.Permission{
					{
						Rule: &xds_rbac.Permission_Any{Any: true},
					},
				},
			},
		},
		{
			name: "testing rule for no principal specified",
			expectedPolicy: &xds_rbac.Policy{
				Principals: []*xds_rbac.Principal{
					{
						Identifier: &xds_rbac.Principal_Any{Any: true},
					},
				},
				Permissions: []*xds_rbac.Permission{
					{
						Rule: &xds_rbac.Permission_Any{Any: true},
					},
				},
			},
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("Testing test case %d: %s", i, tc.name), func(t *testing.T) {
			assert := tassert.New(t)

			pb := &PolicyBuilder{}
			for _, principal := range tc.principals {
				pb.AddPrincipal(principal)
			}
			for _, port := range tc.ports {
				pb.AddAllowedDestinationPort(port)
			}

			pb.UseAndForPermissions(tc.applyPermissionsAsAND)
			policy := pb.Build()
			assert.Equal(policy, tc.expectedPolicy)
		})
	}
}
