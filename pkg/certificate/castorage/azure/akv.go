package azure

import (
	"context"
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	_ "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"

	"github.com/openservicemesh/osm/pkg/certificate"
)

type AKVClient struct {
	version    string
	secretName string

	client   *azsecrets.Client
	vaultURL string
}

func New(vaultURL string, creds azcore.TokenCredential, version string) (*AKVClient, error) {
	client, err := azsecrets.NewClient(vaultURL, creds, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating akv client: %w", err)
	}
	return &AKVClient{
		version:  version,
		client:   client,
		vaultURL: vaultURL,
	}, nil
}

func (c *AKVClient) Get(ctx context.Context) (*certificate.Certificate, error) {
	getResp, err := c.client.GetSecret(ctx, c.secretName, nil)
	if err != nil {
		log.Fatalf("failed to get the secret: %v", err)
	}

	secret := getResp.Value
	if secret == nil {
		return nil, fmt.Errorf("fetched secret %s is stored as nil", c.secretName)
	}
	return certificate.Unmarshal(*secret)
}

func (c *AKVClient) Set(ctx context.Context, cert *certificate.Certificate) (string, error) {
	secret, err := cert.Marshal()
	if err != nil {
		return "", fmt.Errorf("error marshaling certificate: %w", err)
	}
	resp, err := c.client.SetSecret(ctx, cert.GetCommonName().String(), secret, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create a secret for %s: %w", cert.CommonName.String(), err)
	}
	if resp.Properties == nil || resp.Properties.Version == nil {
		return "", fmt.Errorf("unable to get version from response: %w", err)
	}
	return *resp.Properties.Version, nil
}
