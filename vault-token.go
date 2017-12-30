package main

import (
	"encoding/json"
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
	customresource.Register("VaultToken", new(VaultTokenResource))
}

// VaultTokenResource represents `vault audit enable/disable` CloudFormation resource.
type VaultTokenResource struct {
	Role            string            `json:",omitempty"`
	ParameterKey    string            `json:",omitempty"`
	ParameterName   string            `json:",omitempty"`
	Policies        []string          `json:",omitempty"`
	Metadata        map[string]string `json:",omitempty"`
	ExplicitMaxTTL  string            `json:",omitempty"`
	TTL             string            `json:",omitempty"`
	Period          string            `json:",omitempty"`
	UseLimit        string            `json:",omitempty"`
	NoParent        string            `json:",omitempty"`
	NoDefaultPolicy string            `json:",omitempty"`
	Renewable       string            `json:",omitempty"`
	RevokeOnDelete  string            `json:",omitempty"`
}

const (
	tokenParameterInfix = "Vault/Token"
)

func (res *VaultTokenResource) configure(evt *cloudformation.Event) (noParent, noDefaultPolicy bool, renewable *bool, useLimit int, err error) {
	readVaultTokenParameter()

	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return false, false, nil, 0, err
	}

	if res.ParameterName == "" {
		stcknm := strings.Split(evt.StackID, "/")[1]
		res.ParameterName = fmt.Sprintf("/%s/%s/%s", stcknm, tokenParameterInfix, evt.PhysicalResourceID)
	}

	noParent, err = strconv.ParseBool(res.NoParent)
	if err != nil {
		log.Printf("failed to parse `NoParent`: %v", err)
	}
	res.NoParent = fmt.Sprint(noParent)

	noDefaultPolicy, err = strconv.ParseBool(res.NoDefaultPolicy)
	if err != nil {
		log.Printf("failed to parse `NoDefaultPolicy`: %v", err)
	}
	res.NoDefaultPolicy = fmt.Sprint(noDefaultPolicy)

	if b, err := strconv.ParseBool(res.Renewable); err != nil {
		log.Printf("failed to parse `Renewable`: %v", err)
	} else {
		renewable = &b
		res.Renewable = fmt.Sprint(*renewable)
	}

	revokeOnDelete, err := strconv.ParseBool(res.RevokeOnDelete)
	if err != nil {
		log.Printf("failed to parse `RevokeOnDelete`: %v", err)
	}
	res.RevokeOnDelete = fmt.Sprint(revokeOnDelete)

	useLimit, err = strconv.Atoi(res.UseLimit)
	if err != nil {
		log.Printf("failed to parse `UseLimit`: %v", err)
	}
	res.UseLimit = fmt.Sprint(useLimit)

	return noParent, noDefaultPolicy, renewable, useLimit, nil
}

func (res *VaultTokenResource) doCreate(noParent, noDefaultPolicy bool, renewable *bool, useLimit int) error {
	var (
		sec *vaultapi.Secret
		err error
	)

	tcr := &vaultapi.TokenCreateRequest{
		DisplayName:     res.ParameterName,
		ExplicitMaxTTL:  res.ExplicitMaxTTL,
		TTL:             res.TTL,
		Period:          res.Period,
		Metadata:        res.Metadata,
		Policies:        res.Policies,
		NoDefaultPolicy: noDefaultPolicy,
		NoParent:        noParent,
		Renewable:       renewable,
		NumUses:         useLimit,
	}

	if res.Role != "" {
		sec, err = vault.Auth().Token().CreateWithRole(tcr, res.Role)
	} else if noParent {
		sec, err = vault.Auth().Token().CreateOrphan(tcr)
	} else {
		sec, err = vault.Auth().Token().Create(tcr)
	}

	if err != nil {
		return err
	}
	if sec == nil {
		return fmt.Errorf("somehow got a nil secret")
	}
	if sec.Auth == nil {
		return fmt.Errorf("somehow got a nil secret.Auth")
	}

	tpo := &parameterOptions{
		EncryptionKey: res.ParameterKey,
		Overwrite:     true,
	}
	if _, err = putParameter(tpo, res.ParameterName, sec.Auth.ClientToken); err != nil {
		log.Printf("SSM PutParameter Error: %s", err)
		return err
	}

	res.Policies = sec.Auth.Policies
	res.Renewable = fmt.Sprint(sec.Auth.Renewable)
	res.Metadata = sec.Auth.Metadata

	return nil
}

func (res *VaultTokenResource) doRenew(tcreq *vaultapi.TokenCreateRequest) error {
	return fmt.Errorf("not implemented: token-renew")
}

func (res *VaultTokenResource) doRevoke(token string) error {
	if res.RevokeOnDelete != "true" {
		return fmt.Errorf("RevokeOnDelete != true")
	}

	if res.NoParent == "true" {
		log.Printf("Vault Token `%s` - attempting to revoke (orphan)", res.ParameterName)
		return vault.Auth().Token().RevokeOrphan(token)
	}

	log.Printf("Vault Token `%s` - attempting to revoke (tree)", res.ParameterName)
	return vault.Auth().Token().RevokeTree(token)
}

// Create is invoked when the resource is created.
func (res *VaultTokenResource) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := customresource.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid

	noParent, noDefaultPolicy, renewable, useLimit, err := res.configure(evt)
	if err != nil {
		return rid, nil, err
	}

	log.Printf("Vault Token `%s` - attempting to create", res.ParameterName)
	return rid, res, res.doCreate(noParent, noDefaultPolicy, renewable, useLimit)
}

// Update is invoked when the resource is updated.
func (res *VaultTokenResource) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := evt.PhysicalResourceID

	_, _, _, _, err := res.configure(evt)
	if err != nil {
		return rid, nil, err
	}

	log.Printf("Vault Token `%s` - attempting to update (NOT IMPLEMENTED)", res.ParameterName)

	return rid, res, err
}

// Delete is invoked when the resource is deleted.
func (res *VaultTokenResource) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	var token string
	_, _, _, _, err := res.configure(evt)
	if err == nil && res.RevokeOnDelete == "true" {
		token, _, err = getParameter(res.ParameterName)
	}

	if err == nil && token != "" {
		vault.SetMaxRetries(1)
		vault.SetClientTimeout(30 * time.Second)
		log.Printf("Vault Token `%s` - delete with `RevokeOnDelete`", res.ParameterName)
		res.doRevoke(token)
	}

	if err != nil {
		log.Printf("Vault Token `%s` - skipping %s: %v", res.ParameterName, strings.ToLower(evt.RequestType), err)
	}

	return nil
}
