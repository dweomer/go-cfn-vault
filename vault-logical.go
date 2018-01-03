package main

import (
	"encoding/json"
	"errors"
	"log"
	"time"

	customresource "github.com/eawsy/aws-cloudformation-go-customres/service/cloudformation/customres"
	lambdaruntime "github.com/eawsy/aws-lambda-go-core/service/lambda/runtime"
	cloudformation "github.com/eawsy/aws-lambda-go-event/service/lambda/runtime/event/cloudformationevt"
)

func init() {
	res := new(vaultLogicalHandler)
	customresource.Register("VaultData", res)
	customresource.Register("VaultLogical", res)
	customresource.Register("VaultSecret", res)
}

type vaultLogicalHandler struct{}
type vaultLogicalResource struct {
	vaultResource `json:"-"`

	Path string                 `json:",omitempty"`
	Data map[string]interface{} `json:",omitempty"`
}

func (h *vaultLogicalHandler) resource(evt *cloudformation.Event) (string, *vaultLogicalResource, error) {
	rid := resourceID(evt)
	res := &vaultLogicalResource{}

	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return rid, nil, err
	}

	if res.Path == "" {
		return rid, nil, errors.New("missing required resource property `Path`")
	}

	return rid, res, res.initWithTokenParameterOverride()
}

// Create is invoked when the resource is created.
func (h *vaultLogicalHandler) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	return h.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (h *vaultLogicalHandler) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid, res, err := h.resource(evt)
	if err != nil {
		return rid, nil, err
	}

	log.Printf("Vault Logical `%s`: attempting write", res.Path)

	_, err = res.client.Logical().Write(res.Path, res.Data)

	return rid, res, err
}

// Delete is invoked when the resource is deleted.
func (h *vaultLogicalHandler) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	_, res, err := h.resource(evt)

	if err == nil {
		res.client.SetMaxRetries(1)
		res.client.SetClientTimeout(30 * time.Second)
		log.Printf("Vault Logical `%s`: attempting delete", res.Path)
		_, err = res.client.Logical().Delete(res.Path)
	}

	if err != nil {
		log.Printf("Vault Logical `%s` - skipping delete: %v", res.Path, err)
	}

	return nil
}
