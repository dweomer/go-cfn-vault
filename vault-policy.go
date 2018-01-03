package main

import (
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	customresource "github.com/eawsy/aws-cloudformation-go-customres/service/cloudformation/customres"
	lambdaruntime "github.com/eawsy/aws-lambda-go-core/service/lambda/runtime"
	cloudformation "github.com/eawsy/aws-lambda-go-event/service/lambda/runtime/event/cloudformationevt"
)

func init() {
	customresource.Register("VaultPolicy", new(vaultPolicyHandler))
}

type vaultPolicyHandler struct{}
type vaultPolicyResource struct {
	vaultResource `json:"-"`

	Name  string `json:",omitempty"`
	Rules string `json:",omitempty"`
}

func (h *vaultPolicyHandler) resource(evt *cloudformation.Event) (string, *vaultPolicyResource, error) {
	rid := resourceID(evt)
	res := &vaultPolicyResource{}

	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return rid, nil, err
	}

	if res.Name == "" {
		return rid, nil, errors.New("missing required resource property `Name`")
	}
	if res.Rules == "" {
		return rid, nil, errors.New("missing required resource property `Rules`")
	}

	return rid, res, res.initWithTokenParameterOverride()
}

// Create is invoked when the resource is created.
func (h *vaultPolicyHandler) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	return h.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (h *vaultPolicyHandler) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid, res, err := h.resource(evt)
	if err != nil {
		return rid, nil, err
	}

	log.Printf("Vault Policy `%s` - attempting %s:\n%s", res.Name, strings.ToLower(evt.RequestType), res.Rules)

	return rid, res, res.client.Sys().PutPolicy(res.Name, res.Rules)
}

// Delete is invoked when the resource is deleted.
func (h *vaultPolicyHandler) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	_, res, err := h.resource(evt)
	if err == nil {
		res.client.SetMaxRetries(1)
		res.client.SetClientTimeout(30 * time.Second)
		err = res.client.Sys().DeletePolicy(res.Name)
	}

	if err != nil {
		log.Printf("Vault Policy `%s` - skipping delete: %v", res.Name, err)
	}

	return nil
}
