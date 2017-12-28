package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	customresource "github.com/eawsy/aws-cloudformation-go-customres/service/cloudformation/customres"
	lambdaruntime "github.com/eawsy/aws-lambda-go-core/service/lambda/runtime"
	cloudformation "github.com/eawsy/aws-lambda-go-event/service/lambda/runtime/event/cloudformationevt"
	vaultapi "github.com/hashicorp/vault/api"
)

func init() {
	customresource.Register("VaultInit", new(VaultInitResource))
}

const (
	initDefaultScheme = "http"
	initDefaultPort   = "8200"

	initDefaultRootTokenDescription = "Vault Root Token"
	initDefaultRootTokenSuffix      = "Token/Root"

	initDefaultSecretShareDescription = "Vault Unseal Key"
	initDefaultSecretShareSuffix      = "Secret/Unseal"
)

// VaultInitResource represents `vault init` CloudFormation resource.
type VaultInitResource struct {
	ServerScheme string `json:",omitempty"`
	ServerGroup  string `json:",omitempty"`
	ServerPort   string `json:",omitempty"`

	RootTokenEncryptionKey string `json:",omitempty"`
	RootTokenParameterName string `json:",omitempty"`

	SecretShareEncryptionKey string `json:",omitempty"`
	SecretShareParameterName string `json:",omitempty"`

	ShouldUnseal string `json:",omitempty"`
}

// Create is invoked when the resource is created.
func (r *VaultInitResource) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := customresource.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid
	return r.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (r *VaultInitResource) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := evt.PhysicalResourceID

	if err := json.Unmarshal(evt.ResourceProperties, r); err != nil {
		return rid, nil, err
	}

	if r.ServerScheme == "" {
		r.ServerScheme = initDefaultScheme
	}

	if r.ServerGroup == "" {
		return rid, nil, errors.New("missing required resource property `ServerGroup`")
	}

	if r.ServerPort == "" {
		r.ServerScheme = initDefaultPort
	}

	stcknm := strings.Split(evt.StackID, "/")[1]

	if r.RootTokenParameterName == "" {
		r.RootTokenParameterName = fmt.Sprintf("/%s/Vault/%s", stcknm, initDefaultRootTokenSuffix)
	}

	if r.SecretShareParameterName == "" {
		r.SecretShareParameterName = fmt.Sprintf("/%s/Vault/%s", stcknm, initDefaultSecretShareSuffix)
	}

	if r.RootTokenParameterName == r.SecretShareParameterName {
		return rid, nil, errors.New("RootTokenParameterName must be different than SecretShareParameterName")
	}

	vipaddr, err := listInstanceAddressesInGroup(r.ServerGroup)
	if err != nil {
		return rid, nil, err
	}
	if len(vipaddr) == 0 {
		return rid, nil, fmt.Errorf("no suitable instances found in `%s`", r.ServerGroup)
	}

	vconfig := vaultapi.DefaultConfig()
	if err := vconfig.ReadEnvironment(); err != nil {
		return rid, nil, err
	}
	vconfig.Address = fmt.Sprintf("%s://%s:%s", r.ServerScheme, vipaddr[0], r.ServerPort)

	vclient, err := vaultapi.NewClient(vconfig)
	if err != nil {
		return rid, nil, err
	}

	vhealth, err := vclient.Sys().Health()
	for i := 0; err != nil && i < 10; i++ {
		log.Printf("sleeping prior to retry, because: %s", err)
		time.Sleep(5 * time.Second)
		vhealth, err = vclient.Sys().Health()
	}
	log.Printf("Vault Health Response: %+v", vhealth)
	if err != nil {
		return rid, nil, err
	}

	response := map[string]string{
		"SecretShareParameter": r.SecretShareParameterName,
		"RootTokenParameter":   r.RootTokenParameterName,
	}

	if !vhealth.Initialized {
		vinitreq := vaultapi.InitRequest{
			SecretShares:    1,
			SecretThreshold: 1,
		}

		log.Printf("Vault Init Request: %+v", vinitreq)
		vinitres, err := vclient.Sys().Init(&vinitreq)
		// DO NOT LOG THE RESPONSE
		if err != nil {
			log.Printf("Vault Init Error: %s", err)
			return rid, nil, err
		}

		ssopts := &parameterOptions{
			Description:   initDefaultSecretShareDescription,
			EncryptionKey: r.SecretShareEncryptionKey,
			Overwrite:     true,
		}
		if _, err = putParameter(ssopts, r.SecretShareParameterName, vinitres.Keys[0]); err != nil {
			log.Printf("SSM PutParameter Error: %s", err)
			return rid, nil, err
		}

		rtopts := &parameterOptions{
			Description:   initDefaultRootTokenDescription,
			EncryptionKey: r.RootTokenEncryptionKey,
			Overwrite:     true,
		}
		if _, err = putParameter(rtopts, r.RootTokenParameterName, vinitres.RootToken); err != nil {
			log.Printf("SSM PutParameter Error: %s", err)
			return rid, nil, err
		}

		if shouldUnseal, err := strconv.ParseBool(r.ShouldUnseal); err == nil && shouldUnseal && vhealth.Sealed {
			vss, err := vclient.Sys().Unseal(vinitres.Keys[0])
			if err != nil {
				log.Printf("Vault Unseal Error: %s", err)
			}
			log.Printf("Vault Seal Status: %+v", vss)
		}
	}

	return rid, response, nil
}

// Delete is invoked when the resource is deleted.
func (r *VaultInitResource) Delete(*cloudformation.Event, *lambdaruntime.Context) error {
	return nil
}
