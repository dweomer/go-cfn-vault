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

func (res *VaultInitResource) configure(evt *cloudformation.Event) error {
	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return err
	}

	if res.ServerScheme == "" {
		res.ServerScheme = initDefaultScheme
	}

	if res.ServerGroup == "" {
		return errors.New("missing required resource property `ServerGroup`")
	}

	if res.ServerPort == "" {
		res.ServerScheme = initDefaultPort
	}

	stcknm := strings.Split(evt.StackID, "/")[1]

	if res.RootTokenParameterName == "" {
		res.RootTokenParameterName = fmt.Sprintf("/%s/Vault/%s", stcknm, initDefaultRootTokenSuffix)
	}

	if res.SecretShareParameterName == "" {
		res.SecretShareParameterName = fmt.Sprintf("/%s/Vault/%s", stcknm, initDefaultSecretShareSuffix)
	}

	if res.RootTokenParameterName == res.SecretShareParameterName {
		return errors.New("RootTokenParameterName must be different than SecretShareParameterName")
	}

	return nil
}

// Create is invoked when the resource is created.
func (res *VaultInitResource) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := customresource.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid
	return res.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (res *VaultInitResource) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := evt.PhysicalResourceID

	if err := res.configure(evt); err != nil {
		return rid, nil, err
	}

	vipaddr, err := listInstanceAddressesInGroup(res.ServerGroup)
	if err != nil {
		return rid, nil, err
	}
	if len(vipaddr) == 0 {
		return rid, nil, fmt.Errorf("no suitable instances found in `%s`", res.ServerGroup)
	}

	if err := vault.SetAddress(fmt.Sprintf("%s://%s:%s", res.ServerScheme, vipaddr[0], res.ServerPort)); err != nil {
		return rid, nil, err
	}

	vhealth, err := vault.Sys().Health()
	for i := 0; err != nil && i < 10; i++ {
		log.Printf("sleeping prior to retry, because: %s", err)
		time.Sleep(5 * time.Second)
		vhealth, err = vault.Sys().Health()
	}
	log.Printf("Vault Health Response: %+v", vhealth)
	if err != nil {
		return rid, nil, err
	}

	response := map[string]string{
		"SecretShareParameter": res.SecretShareParameterName,
		"RootTokenParameter":   res.RootTokenParameterName,
	}

	if !vhealth.Initialized {
		vinitreq := vaultapi.InitRequest{
			SecretShares:    1,
			SecretThreshold: 1,
		}

		log.Printf("Vault Init Request: %+v", vinitreq)
		vinitres, err := vault.Sys().Init(&vinitreq)
		// DO NOT LOG THE RESPONSE
		if err != nil {
			log.Printf("Vault Init Error: %s", err)
			return rid, nil, err
		}

		ssopts := &parameterOptions{
			Description:   initDefaultSecretShareDescription,
			EncryptionKey: res.SecretShareEncryptionKey,
			Overwrite:     true,
		}
		if _, err = putParameter(ssopts, res.SecretShareParameterName, vinitres.Keys[0]); err != nil {
			log.Printf("SSM PutParameter Error: %s", err)
			return rid, nil, err
		}

		rtopts := &parameterOptions{
			Description:   initDefaultRootTokenDescription,
			EncryptionKey: res.RootTokenEncryptionKey,
			Overwrite:     true,
		}
		if _, err = putParameter(rtopts, res.RootTokenParameterName, vinitres.RootToken); err != nil {
			log.Printf("SSM PutParameter Error: %s", err)
			return rid, nil, err
		}

		if shouldUnseal, err := strconv.ParseBool(res.ShouldUnseal); err == nil && shouldUnseal && vhealth.Sealed {
			vss, err := vault.Sys().Unseal(vinitres.Keys[0])
			if err != nil {
				log.Printf("Vault Unseal Error: %s", err)
			}
			log.Printf("Vault Seal Status: %+v", vss)
		}
	}

	return rid, response, nil
}

// Delete is invoked when the resource is deleted.
func (res *VaultInitResource) Delete(*cloudformation.Event, *lambdaruntime.Context) error {
	return nil
}
