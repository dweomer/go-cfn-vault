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
	res := new(VaultLogicalResource)
	customresource.Register("VaultData", res)
	customresource.Register("VaultLogical", res)
	customresource.Register("VaultSecret", res)
	customresource.Register("VaultPath", res)
}

// VaultLogicalResource represents `vault audit enable/disable` CloudFormation resource.
type VaultLogicalResource struct {
	Path string                 `json:",omitempty"`
	Data map[string]interface{} `json:",omitempty"`
}

func (res *VaultLogicalResource) configure(evt *cloudformation.Event) error {
	readVaultTokenParameter()

	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return err
	}

	if res.Path == "" {
		return errors.New("missing required resource property `Path`")
	}

	return nil
}

// Create is invoked when the resource is created.
func (res *VaultLogicalResource) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := customresource.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid
	return res.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (res *VaultLogicalResource) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := evt.PhysicalResourceID
	err := res.configure(evt)
	if err != nil {
		return rid, nil, err
	}

	log.Printf("Vault Logical `%s`: attempting write", res.Path)
	_, err = vault.Logical().Write(res.Path, res.Data)
	return rid, res, err
}

// Delete is invoked when the resource is deleted.
func (res *VaultLogicalResource) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	err := res.configure(evt)

	if err == nil {
		vault.SetMaxRetries(1)
		vault.SetClientTimeout(30 * time.Second)
		log.Printf("Vault Logical `%s`: attempting delete", res.Path)
		_, err = vault.Logical().Delete(res.Path)
	}

	if err != nil {
		log.Printf("Vault Logical `%s` - skipping delete: %v", res.Path, err)
	}

	return nil
}
