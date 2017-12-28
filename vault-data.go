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
	customresource.Register("VaultData", new(VaultDataResource))
}

// VaultDataResource represents `vault audit enable/disable` CloudFormation resource.
type VaultDataResource struct {
	Path string                 `json:",omitempty"`
	Data map[string]interface{} `json:",omitempty"`
}

func (res *VaultDataResource) configure(evt *cloudformation.Event) error {
	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return err
	}

	if res.Path == "" {
		return errors.New("missing required resource property `Path`")
	}

	return nil
}

// Create is invoked when the resource is created.
func (res *VaultDataResource) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := customresource.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid
	return res.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (res *VaultDataResource) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := evt.PhysicalResourceID
	err := res.configure(evt)
	if err != nil {
		return rid, nil, err
	}

	log.Printf("Vault Write  - `%s`", res.Path)
	_, err = vault.Logical().Write(res.Path, res.Data)
	return rid, res, err
}

// Delete is invoked when the resource is deleted.
func (res *VaultDataResource) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	err := res.configure(evt)

	if err == nil {
		vault.SetMaxRetries(1)
		vault.SetClientTimeout(30 * time.Second)
		log.Printf("Vault Delete  - `%s`", res.Path)
		_, err = vault.Logical().Delete(res.Path)
	}

	if err != nil {
		log.Printf("Vault Delete - skipping `%s`: %v", res.Path, err)
	}

	return nil
}
