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
	customresource.Register("VaultToken", new(vaultTokenHandler))
}

type vaultTokenHandler struct{}
type vaultTokenResource struct {
	vaultResource `json:"-"`

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

func (h *vaultTokenHandler) resource(evt *cloudformation.Event) (string, *vaultTokenResource, error) {
	rid := resourceID(evt)
	res := &vaultTokenResource{}

	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return rid, nil, err
	}

	if res.ParameterName == "" {
		stcknm := strings.Split(evt.StackID, "/")[1]
		res.ParameterName = fmt.Sprintf("/%s/%s/%s", stcknm, tokenParameterInfix, evt.PhysicalResourceID)
	}

	noParent, err := strconv.ParseBool(res.NoParent)
	if err != nil {
		log.Printf("failed to parse `NoParent`: %v", err)
	}
	res.NoParent = fmt.Sprint(noParent)

	noDefaultPolicy, err := strconv.ParseBool(res.NoDefaultPolicy)
	if err != nil {
		log.Printf("failed to parse `NoDefaultPolicy`: %v", err)
	}
	res.NoDefaultPolicy = fmt.Sprint(noDefaultPolicy)

	if b, err := strconv.ParseBool(res.Renewable); err != nil {
		log.Printf("failed to parse `Renewable`: %v", err)
	} else {
		renewable := &b
		res.Renewable = fmt.Sprint(*renewable)
	}

	revokeOnDelete, err := strconv.ParseBool(res.RevokeOnDelete)
	if err != nil {
		log.Printf("failed to parse `RevokeOnDelete`: %v", err)
	}
	res.RevokeOnDelete = fmt.Sprint(revokeOnDelete)

	useLimit, err := strconv.Atoi(res.UseLimit)
	if err != nil {
		log.Printf("failed to parse `UseLimit`: %v", err)
	}
	res.UseLimit = fmt.Sprint(useLimit)

	return rid, res, res.initWithTokenParameterOverride()
}

const (
	tokenParameterInfix = "Vault/Token"
)

// Create is invoked when the resource is created.
func (h *vaultTokenHandler) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid, res, err := h.resource(evt)
	if err != nil {
		return rid, nil, err
	}

	log.Printf("Vault Token `%s` - attempting to create", res.ParameterName)

	return rid, res, res.doCreate()
}

// Update is invoked when the resource is updated.
func (h *vaultTokenHandler) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid, res, err := h.resource(evt)
	if err != nil {
		return rid, nil, err
	}

	log.Printf("Vault Token `%s` - attempting to update (NOT IMPLEMENTED)", res.ParameterName)

	return rid, res, nil
}

// Delete is invoked when the resource is deleted.
func (h *vaultTokenHandler) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	_, res, err := h.resource(evt)
	if err == nil && res.RevokeOnDelete == "true" && res.ParameterName != "" {
		res.client.SetMaxRetries(1)
		res.client.SetClientTimeout(30 * time.Second)
		log.Printf("Vault Token `%s` - delete with `RevokeOnDelete`", res.ParameterName)
		err = res.doRevoke()
	}

	if err != nil {
		log.Printf("Vault Token `%s` - skipping delete: %v", res.ParameterName, err)
	}

	return nil
}

func (res *vaultTokenResource) doCreate() error {
	var (
		sec *vaultapi.Secret
		err error
	)

	isRenewable := res.Renewable == "true"
	useLimit, _ := strconv.ParseInt(res.UseLimit, 10, 64)

	tcr := &vaultapi.TokenCreateRequest{
		DisplayName:     res.ParameterName,
		ExplicitMaxTTL:  res.ExplicitMaxTTL,
		TTL:             res.TTL,
		Period:          res.Period,
		Metadata:        res.Metadata,
		Policies:        res.Policies,
		NoDefaultPolicy: res.NoDefaultPolicy == "true",
		NoParent:        res.NoParent == "true",
		Renewable:       &isRenewable,
		NumUses:         int(useLimit),
	}

	if res.Role != "" {
		sec, err = res.client.Auth().Token().CreateWithRole(tcr, res.Role)
	} else if tcr.NoParent {
		sec, err = res.client.Auth().Token().CreateOrphan(tcr)
	} else {
		sec, err = res.client.Auth().Token().Create(tcr)
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

func (res *vaultTokenResource) doRenew() error {
	return fmt.Errorf("not implemented: token-renew")
}

func (res *vaultTokenResource) doRevoke() error {
	if res.RevokeOnDelete != "true" {
		return fmt.Errorf("RevokeOnDelete is not true")
	}

	if res.NoParent == "true" {
		log.Printf("Vault Token `%s` - attempting to revoke (orphan)", res.ParameterName)
		return res.client.Auth().Token().RevokeOrphan(res.ParameterName)
	}

	log.Printf("Vault Token `%s` - attempting to revoke (tree)", res.ParameterName)
	return res.client.Auth().Token().RevokeTree(res.ParameterName)
}
