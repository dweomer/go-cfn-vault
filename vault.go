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
}

func readVaultTokenParameter() {
	if vtpn := os.Getenv("VAULT_TOKEN_PARAMETER"); vtpn != "" {
		log.Printf("$VAULT_TOKEN_PARAMETER='%s', reading parameter value ...", vtpn)
		vtpv, _, err := getParameter(vtpn)
		if err != nil {
			log.Printf("$VAULT_TOKEN_PARAMETER='%s', unable to read parameter: %v", vtpn, err)
		} else {
			log.Printf("$VAULT_TOKEN_PARAMETER='%s', setting parameter value on client", vtpn)
			vault.SetToken(vtpv)
		}
	} else {
		log.Printf("$VAULT_TOKEN_PARAMETER is empty or not present")
	}
}

// Happy IDE means happy developer.
func main() {
}
