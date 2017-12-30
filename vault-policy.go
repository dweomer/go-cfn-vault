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
	customresource.Register("VaultPolicy", new(VaultPolicyResource))
}

// VaultPolicyResource represents `vault audit enable/disable` CloudFormation resource.
type VaultPolicyResource struct {
	Name  string `json:",omitempty"`
	Rules string `json:",omitempty"`
}

func (res *VaultPolicyResource) configure(evt *cloudformation.Event) error {
	readVaultTokenParameter()

	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return err
	}

	if res.Name == "" {
		return errors.New("missing required resource property `Name`")
	}
	if res.Rules == "" {
		return errors.New("missing required resource property `Rules`")
	}

	return nil
}

// Create is invoked when the resource is created.
func (res *VaultPolicyResource) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := customresource.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid
	return res.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (res *VaultPolicyResource) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := evt.PhysicalResourceID
	err := res.configure(evt)
	if err != nil {
		return rid, nil, err
	}

	log.Printf("Vault Policy (write) - `%s`:\n%s", res.Name, res.Rules)
	return rid, res, vault.Sys().PutPolicy(res.Name, res.Rules)
}

// Delete is invoked when the resource is deleted.
func (res *VaultPolicyResource) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	err := res.configure(evt)

	if err == nil {
		vault.SetMaxRetries(1)
		vault.SetClientTimeout(30 * time.Second)
		err = vault.Sys().DeletePolicy(res.Name)
	}

	if err != nil {
		log.Printf("Vault Policy (delete) - skipping: %v", err)
	}

	return nil
}
