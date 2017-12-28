package main

import (
	"log"
	"os"

	customresource "github.com/eawsy/aws-cloudformation-go-customres/service/cloudformation/customres"
	vaultapi "github.com/hashicorp/vault/api"
)

var (
	// Handle is the Lambda's entrypoint.
	Handle customresource.LambdaHandler

	vault *vaultapi.Client
)

func init() {
	Handle = customresource.HandleLambda

	vcfg := vaultapi.DefaultConfig()

	if verr := vcfg.ReadEnvironment(); verr != nil {
		panic(verr)
	}

	if vapi, verr := vaultapi.NewClient(vcfg); verr != nil {
		panic(verr)
	} else {
		vault = vapi
	}

	if vtpn := os.Getenv("VAULT_TOKEN_PARAMETER"); vtpn != "" {
		vtpv, _, err := getParameter(vtpn)
		if err != nil {
			log.Printf("unable to read parameter token: %v", err)
		} else {
			vault.SetToken(vtpv)
		}
	}
}

// Happy IDE means happy developer.
func main() {
}
