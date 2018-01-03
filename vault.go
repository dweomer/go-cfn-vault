package main

import (
	"log"
	"os"

	customresource "github.com/eawsy/aws-cloudformation-go-customres/service/cloudformation/customres"
	cloudformation "github.com/eawsy/aws-lambda-go-event/service/lambda/runtime/event/cloudformationevt"
	vaultapi "github.com/hashicorp/vault/api"
)

var (
	// Handle is the Lambda's entrypoint.
	Handle customresource.LambdaHandler
)

func init() {
	Handle = customresource.HandleLambda
}

type vaultHandler struct{}

func resourceID(evt *cloudformation.Event) string {
	if evt.PhysicalResourceID == "" {
		return customresource.NewPhysicalResourceID(evt)
	}
	return evt.PhysicalResourceID
}

type vaultResource struct {
	client *vaultapi.Client
}

func (res *vaultResource) init() error {
	vcfg := vaultapi.DefaultConfig()

	if verr := vcfg.ReadEnvironment(); verr != nil {
		return verr
	}

	vapi, verr := vaultapi.NewClient(vcfg)
	if verr != nil {
		return verr
	}
	res.client = vapi

	return nil
}

func (res *vaultResource) initWithTokenParameterOverride() error {
	if err := res.init(); err != nil {
		return err
	}

	if vtpn := os.Getenv("VAULT_TOKEN_PARAMETER"); vtpn != "" {
		log.Printf("$VAULT_TOKEN_PARAMETER='%s', reading parameter value ...", vtpn)
		vtpv, _, err := getParameter(vtpn)
		if err != nil {
			log.Printf("$VAULT_TOKEN_PARAMETER='%s', unable to read parameter: %v", vtpn, err)
		} else {
			log.Printf("$VAULT_TOKEN_PARAMETER='%s', setting parameter value on client", vtpn)
			res.client.SetToken(vtpv)
		}
	} else {
		log.Printf("$VAULT_TOKEN_PARAMETER is empty or not present")
	}

	return nil
}

// Happy IDE means happy developer.
func main() {
}
