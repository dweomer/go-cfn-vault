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
	customresource.Register("VaultInit", new(vaultInitHandler))
}

const (
	initDefaultScheme = "http"
	initDefaultPort   = "8200"

	initDefaultRootTokenDescription = "Vault Root Token"
	initDefaultRootTokenSuffix      = "Token/Root"

	initDefaultSecretShareDescription = "Vault Unseal Key"
	initDefaultSecretShareSuffix      = "Secret/Unseal"

	initDefaultSecretShares    = 5
	initDefaultSecretThreshold = 3
)

var (
	errSupposedlyUnpossibleInitilizationStateMismatch = fmt.Errorf("supposedly unpossible initialization state mismatch with group")
)

type vaultInitHandler struct{}
type vaultInitResource struct {
	vaultResource `json:"-"`

	ServerScheme string `json:",omitempty"`
	ServerGroup  string `json:",omitempty"`
	ServerPort   string `json:",omitempty"`

	RootTokenEncryptionKey string `json:",omitempty"`
	RootTokenParameterName string `json:",omitempty"`

	SecretShareEncryptionKey string `json:",omitempty"`
	SecretShareParameterName string `json:",omitempty"`

	SecretShares    string `json:",omitempty"`
	SecretThreshold string `json:",omitempty"`
	ShouldUnseal    string `json:",omitempty"`
}

func (h *vaultInitHandler) resource(evt *cloudformation.Event) (string, *vaultInitResource, error) {
	rid := resourceID(evt)
	res := &vaultInitResource{}

	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return rid, nil, err
	}

	if res.ServerScheme == "" {
		res.ServerScheme = initDefaultScheme
	}

	if res.ServerGroup == "" {
		return rid, nil, errors.New("missing required resource property `ServerGroup`")
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
		return rid, nil, errors.New("RootTokenParameterName must be different than SecretShareParameterName")
	}

	secretShares, err := strconv.Atoi(res.SecretShares)
	if err != nil {
		log.Printf("failed to parse `SecretShares`: %v", err)
		secretShares = initDefaultSecretShares
	}
	res.SecretShares = fmt.Sprint(secretShares)

	secretThreshold, err := strconv.Atoi(res.SecretThreshold)
	if err != nil {
		log.Printf("failed to parse `SecretThreshold`: %v", err)
		secretThreshold = initDefaultSecretThreshold
	}
	if secretThreshold > secretShares {
		secretThreshold = secretShares
	}
	res.SecretThreshold = fmt.Sprint(secretThreshold)

	return rid, res, res.init()
}

// Create is invoked when the resource is created.
func (h *vaultInitHandler) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	return h.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (h *vaultInitHandler) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid, res, err := h.resource(evt)
	if err != nil {
		return rid, nil, err
	}

	// override default retry and timeout configuration to give us more control over timing
	res.client.SetMaxRetries(0)
	res.client.SetClientTimeout(10 * time.Second)

	instanceAddr, err := listInstanceAddressesInGroup(res.ServerGroup)
	if err != nil {
		return rid, nil, err
	}

	instanceCount := len(instanceAddr)
	if instanceCount == 0 {
		return rid, nil, fmt.Errorf("no suitable instances found in group `%s`", res.ServerGroup)
	}

	// translate ip addresses to vault addresses
	vaultAddr := make(map[string]string, instanceCount)
	for _, iip := range instanceAddr {
		vaultAddr[iip] = fmt.Sprintf("%s://%s:%s", res.ServerScheme, iip, res.ServerPort)
	}

	for err := res.doHealth(vaultAddr); len(err) > 0; err = res.doHealth(vaultAddr) {
		// bail on fatal error condition
		for _, e := range err {
			if e == errSupposedlyUnpossibleInitilizationStateMismatch {
				return rid, nil, e
			}
		}
		// if every vault is erroring out, lets wait then retry
		if len(err) == len(vaultAddr) {
			time.Sleep(5 * time.Second)
		} else { // zero out the bad apples
			for i := range err {
				delete(vaultAddr, i)
			}
			break
		}
	}

	return rid, res, res.doInitialize(vaultAddr)
}

// Delete is invoked when the resource is deleted.
func (h *vaultInitHandler) Delete(*cloudformation.Event, *lambdaruntime.Context) error {
	return nil
}

func (res *vaultInitResource) doHealth(group map[string]string) map[string]error {
	errors := make(map[string]error, len(group))

	var initialized *bool

	for ip, addr := range group {
		if err := res.client.SetAddress(addr); err != nil {
			errors[ip] = err
		} else if health, err := res.client.Sys().Health(); err != nil {
			log.Printf("Vault Init `%s` - Health: %+v", addr, err)
			errors[ip] = err
		} else {
			log.Printf("Vault Init `%s` - Health: %+v", addr, health)
			if initialized == nil {
				initialized = &health.Initialized
			} else if *initialized != health.Initialized {
				errors[ip] = errSupposedlyUnpossibleInitilizationStateMismatch
			}
		}
	}

	return errors
}

func (res *vaultInitResource) doInitialize(group map[string]string) error {
	var secretShares []string

	for _, addr := range group {
		if err := res.client.SetAddress(addr); err != nil {
			return err
		}

		health, err := res.client.Sys().Health()
		if err != nil {
			log.Printf("Vault Init `%s` - Health: %+v", addr, err)
			return err
		}
		log.Printf("Vault Init `%s` - Health: %+v", addr, health)

		if !health.Initialized && len(secretShares) > 0 {
			return errSupposedlyUnpossibleInitilizationStateMismatch
		}

		if !health.Initialized {
			vii := vaultapi.InitRequest{}
			vii.SecretShares, _ = strconv.Atoi(res.SecretShares)
			vii.SecretThreshold, _ = strconv.Atoi(res.SecretThreshold)

			log.Printf("Vault Init `%s`: %+v", addr, vii)
			vio, err := res.client.Sys().Init(&vii)
			// DO NOT LOG THE RESPONSE
			if err != nil {
				log.Printf("Vault Init `%s`: %s", addr, err)
				return err
			}

			rtopts := &parameterOptions{
				Description:   initDefaultRootTokenDescription,
				EncryptionKey: res.RootTokenEncryptionKey,
				Overwrite:     false,
			}
			if _, err = putParameter(rtopts, res.RootTokenParameterName, vio.RootToken); err != nil {
				log.Printf("Vault Init `%s` - Parameter: %s", addr, err)
				return err
			}

			secretShares = vio.Keys

			for i, shard := range secretShares {
				ssopts := &parameterOptions{
					Description:   initDefaultSecretShareDescription,
					EncryptionKey: res.SecretShareEncryptionKey,
					Overwrite:     false,
				}
				ssparm := fmt.Sprintf("%s/%d", res.SecretShareParameterName, i+1)
				if _, err = putParameter(ssopts, ssparm, shard); err != nil {
					log.Printf("Vault Init `%s` - Parameter: %s", addr, err)
					return err
				}
			}
		}

		if res.ShouldUnseal == "true" && len(secretShares) > 0 {
			for _, shard := range secretShares {
				status, err := res.client.Sys().Unseal(shard)
				if err != nil {
					log.Printf("Vault Init `%s` - Unseal: %s", addr, err)
				} else {
					log.Printf("Vault Init `%s` - Unseal: %+v", addr, status)
					if !status.Sealed {
						break
					}
				}
			}
		}
	}

	return nil
}
