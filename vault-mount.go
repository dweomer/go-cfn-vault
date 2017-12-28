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
	customresource.Register("VaultMount", new(VaultMountResource))
}

var (
	mountGlobalDefaultLeaseTTL = 0
	mountGlobalMaximumLeaseTTL = 0
)

// VaultMountResource represents `vault audit enable/disable` CloudFormation resource.
type VaultMountResource struct {
	Type        string `json:",omitempty"`
	Path        string `json:",omitempty"`
	Description string `json:",omitempty"`

	DefaultLeaseTTL string `json:",omitempty"`
	MaximumLeaseTTL string `json:",omitempty"`
	ForceNoCache    string `json:",omitempty"`

	TuneOnly string `json:",omitempty"`
}

func (res *VaultMountResource) configure(evt *cloudformation.Event) (tune bool, err error) {
	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return false, err
	}

	if res.Type == "" && res.Path == "" {
		return tune, errors.New("missing required resource property, one of `Type` or `Path`")
	}

	if res.Type == "" && res.TuneOnly == "" {
		tune = true
	} else {
		if tune, err = strconv.ParseBool(res.TuneOnly); err != nil {
			log.Printf("failed to parse `TuneOnly`: %v", err)
		}
	}
	res.TuneOnly = fmt.Sprint(tune)

	if res.Path == "" {
		res.Path = res.Type
	}
	if !strings.HasSuffix(res.Path, "/") {
		res.Path += "/"
	}

	return tune, nil
}

func (res *VaultMountResource) doTune() error {
	if res.Path == "" {
		return fmt.Errorf("unspecified `Path`")
	}

	mci := vaultapi.MountConfigInput{
		DefaultLeaseTTL: res.DefaultLeaseTTL,
		MaxLeaseTTL:     res.MaximumLeaseTTL,
	}
	mci.ForceNoCache, _ = strconv.ParseBool(res.ForceNoCache)
	log.Printf("Vault Mount `%s` - attempting to tune", res.Path)
	if err := vault.Sys().TuneMount(res.Path, mci); err != nil {
		return err
	}
	mco, err := vault.Sys().MountConfig(res.Path)
	if err != nil {
		return err
	}
	res.DefaultLeaseTTL = fmt.Sprint(mco.DefaultLeaseTTL)
	res.MaximumLeaseTTL = fmt.Sprint(mco.MaxLeaseTTL)
	res.ForceNoCache = fmt.Sprint(mco.ForceNoCache)

	return nil
}

func (res *VaultMountResource) doMount() error {
	if res.Path == "" {
		return fmt.Errorf("unspecified `Path`")
	}
	mci := vaultapi.MountConfigInput{
		DefaultLeaseTTL: res.DefaultLeaseTTL,
		MaxLeaseTTL:     res.MaximumLeaseTTL,
	}
	mci.ForceNoCache, _ = strconv.ParseBool(res.ForceNoCache)
	mri := vaultapi.MountInput{
		Type:        res.Type,
		Description: res.Description,
		Config:      mci,
	}
	log.Printf("Vault Mount `%s` - attempting to mount", res.Path)
	err := vault.Sys().Mount(res.Path, &mri)
	if err != nil {
		return err
	}

	mco, err := vault.Sys().MountConfig(res.Path)
	if err != nil {
		return err
	}
	res.DefaultLeaseTTL = fmt.Sprint(mco.DefaultLeaseTTL)
	res.MaximumLeaseTTL = fmt.Sprint(mco.MaxLeaseTTL)
	res.ForceNoCache = fmt.Sprint(mco.ForceNoCache)

	return nil
}

func (res *VaultMountResource) doUnmount() error {
	if res.Path == "" {
		return fmt.Errorf("unspecified `Path`")
	}
	if res.TuneOnly == "true" {
		return fmt.Errorf("`%s` configured as `TuneOnly`", res.Path)
	}
	log.Printf("Vault Mount `%s` - attempting to unmount", res.Path)
	return vault.Sys().Unmount(res.Path)
}

// Create is invoked when the resource is created.
func (res *VaultMountResource) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := customresource.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid

	tune, err := res.configure(evt)
	if err != nil {
		return rid, nil, err
	}
	if tune {
		err = res.doTune()
	} else {
		err = res.doMount()
	}
	return rid, res, err
}

// Update is invoked when the resource is updated.
func (res *VaultMountResource) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := evt.PhysicalResourceID

	tune, err := res.configure(evt)
	if err != nil {
		return rid, nil, err
	}
	if tune {
		return rid, res, res.doTune()
	}

	mounts, err := vault.Sys().ListMounts()
	if err != nil {
		return rid, nil, err
	}

	if m, ok := mounts[res.Path]; ok {
		res.Description = m.Description
		log.Printf("Vault Mount `%s` - exists", res.Path)
		return rid, res, res.doTune()
	}

	log.Printf("Vault Mount `%s` - not found", res.Path)
	return rid, res, res.doMount()
}

// Delete is invoked when the resource is deleted.
func (res *VaultMountResource) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	_, err := res.configure(evt)

	if err == nil {
		vault.SetMaxRetries(1)
		vault.SetClientTimeout(30 * time.Second)
		err = res.doUnmount()
	}

	if err != nil {
		log.Printf("Vault Mount - skipping: %v", err)
	}

	return nil
}
