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
	ID              string            `json:"-"`
	Role            string            `json:",omitempty"`
	ParameterKey    string            `json:",omitempty"`
	ParameterName   string            `json:",omitempty"`
	Policies        []string          `json:",omitempty"`
	Metadata        map[string]string `json:",omitempty"`
	TTL             string            `json:",omitempty"`
	ExplicitMaxTTL  string            `json:",omitempty"`
	UseLimit        string            `json:",omitempty"`
	NoParent        string            `json:",omitempty"`
	NoDefaultPolicy string            `json:",omitempty"`
	Renewable       string            `json:",omitempty"`
	RevokeOnDelete  string            `json:",omitempty"`
}

const (
	tokenParameterInfix = "Vault/Token"
)

func (res *VaultTokenResource) configure(evt *cloudformation.Event) (tcreq *vaultapi.TokenCreateRequest, err error) {
	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return nil, err
	}

	if res.ParameterName == "" {
		stcknm := strings.Split(evt.StackID, "/")[1]
		res.ParameterName = fmt.Sprintf("/%s/%s/%s", stcknm, tokenParameterInfix, evt.PhysicalResourceID)
	}

	tcreq = &vaultapi.TokenCreateRequest{
		DisplayName:    res.ParameterName,
		ExplicitMaxTTL: res.ExplicitMaxTTL,
		TTL:            res.TTL,
		Metadata:       res.Metadata,
		Policies:       res.Policies,
	}

	tcreq.NoParent, err = strconv.ParseBool(res.NoParent)
	if err != nil {
		log.Printf("failed to parse `NoParent`: %v", err)
	}
	res.NoParent = fmt.Sprint(tcreq.NoParent)

	tcreq.NoDefaultPolicy, err = strconv.ParseBool(res.NoDefaultPolicy)
	if err != nil {
		log.Printf("failed to parse `NoDefaultPolicy`: %v", err)
	}
	res.NoDefaultPolicy = fmt.Sprint(tcreq.NoDefaultPolicy)

	if renewable, err := strconv.ParseBool(res.Renewable); err != nil {
		log.Printf("failed to parse `Renewable`: %v", err)
	} else {
		tcreq.Renewable = &renewable
		res.Renewable = fmt.Sprint(renewable)
	}

	revokeOnDelete, err := strconv.ParseBool(res.RevokeOnDelete)
	if err != nil {
		log.Printf("failed to parse `RevokeOnDelete`: %v", err)
	}
	res.RevokeOnDelete = fmt.Sprint(revokeOnDelete)

	if tcreq.NumUses, err = strconv.Atoi(res.UseLimit); err != nil {
		log.Printf("failed to parse `UseLimit`: %v", err)
	}
	res.UseLimit = fmt.Sprint(tcreq.NumUses)

	return tcreq, err
}

func (res *VaultTokenResource) doCreate(tcreq *vaultapi.TokenCreateRequest) error {
	return nil
}

func (res *VaultTokenResource) doRenew(tcreq *vaultapi.TokenCreateRequest) error {
	return fmt.Errorf("not implemented: token-renew")
}

func (res *VaultTokenResource) doRevoke(tcreq *vaultapi.TokenCreateRequest) error {
	if res.RevokeOnDelete != "true" {

	}
	return fmt.Errorf("not implemented: token-revoke")
}

// Create is invoked when the resource is created.
func (res *VaultTokenResource) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := customresource.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid

	tcr, err := res.configure(evt)
	if err != nil {
		return rid, nil, err
	}

	log.Printf("Vault Token `%s` - attempting to %s", res.ParameterName, strings.ToLower(evt.RequestType))
	return rid, res, res.doCreate(tcr)
}

// Update is invoked when the resource is updated.
func (res *VaultTokenResource) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := evt.PhysicalResourceID

	tcr, err := res.configure(evt)
	if err != nil {
		return rid, nil, err
	}

	log.Printf("Vault Token `%s` - attempting to %s", res.ParameterName, strings.ToLower(evt.RequestType))

	return rid, res, err
}

// Delete is invoked when the resource is deleted.
func (res *VaultTokenResource) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	tcr, err := res.configure(evt)

	if err == nil && res.RevokeOnDelete == "true" {
		res.ID, _, err = getParameter(res.ParameterName)
	}

	if err == nil && res.ID != "" {
		vault.SetMaxRetries(1)
		vault.SetClientTimeout(30 * time.Second)
		log.Printf("Vault Token `%s` - delete with `RevokeOnDelete`", res.ParameterName)
		res.doRevoke(tcr)
	}

	if err != nil {
		log.Printf("Vault Token `%s` - skipping %s: %v", res.ParameterName, strings.ToLower(evt.RequestType), err)
	}

	return nil
}
