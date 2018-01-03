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
	customresource.Register("VaultMount", new(vaultMountHandler))
}

var (
	mountGlobalDefaultLeaseTTL = 0
	mountGlobalMaximumLeaseTTL = 0
)

type vaultMountHandler struct{}
type vaultMountResource struct {
	vaultResource `json:"-"`

	Type        string `json:",omitempty"`
	Path        string `json:",omitempty"`
	Description string `json:",omitempty"`

	DefaultLeaseTTL string `json:",omitempty"`
	MaximumLeaseTTL string `json:",omitempty"`
	ForceNoCache    string `json:",omitempty"`

	TuneOnly string `json:",omitempty"`
}

func (h *vaultMountHandler) resource(evt *cloudformation.Event) (string, *vaultMountResource, error) {
	rid := resourceID(evt)
	res := &vaultMountResource{}

	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return rid, nil, err
	}

	if res.Type == "" && res.Path == "" {
		return rid, nil, errors.New("missing required resource property, one of `Type` or `Path`")
	}

	tuneOnly := false
	if res.Type == "" && res.TuneOnly == "" {
		tuneOnly = true
	} else {
		if b, err := strconv.ParseBool(res.TuneOnly); err != nil {
			log.Printf("failed to parse `TuneOnly`: %v", err)
		} else {
			tuneOnly = b
		}
	}
	res.TuneOnly = fmt.Sprint(tuneOnly)

	if res.Path == "" {
		res.Path = res.Type
	}
	if !strings.HasSuffix(res.Path, "/") {
		res.Path += "/"
	}

	return rid, res, res.initWithTokenParameterOverride()
}

// Create is invoked when the resource is created.
func (h *vaultMountHandler) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid, res, err := h.resource(evt)
	if err != nil {
		return rid, nil, err
	}

	if res.TuneOnly == "true" {
		err = res.doTune()
	} else {
		err = res.doMount()
	}

	return rid, res, err
}

// Update is invoked when the resource is updated.
func (h *vaultMountHandler) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid, res, err := h.resource(evt)
	if err != nil {
		return rid, nil, err
	}

	if res.TuneOnly == "true" {
		return rid, res, res.doTune()
	}

	mounts, err := res.client.Sys().ListMounts()
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
func (h *vaultMountHandler) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	_, res, err := h.resource(evt)

	if err == nil {
		res.client.SetMaxRetries(1)
		res.client.SetClientTimeout(30 * time.Second)
		err = res.doUnmount()
	}

	if err != nil {
		log.Printf("Vault Mount - skipping delete: %v", err)
	}

	return nil
}

func (res *vaultMountResource) doTune() error {
	if res.Path == "" {
		return fmt.Errorf("unspecified `Path`")
	}

	mci := vaultapi.MountConfigInput{
		DefaultLeaseTTL: res.DefaultLeaseTTL,
		MaxLeaseTTL:     res.MaximumLeaseTTL,
	}
	mci.ForceNoCache, _ = strconv.ParseBool(res.ForceNoCache)
	log.Printf("Vault Mount `%s` - attempting to tune", res.Path)
	if err := res.client.Sys().TuneMount(res.Path, mci); err != nil {
		return err
	}
	mco, err := res.client.Sys().MountConfig(res.Path)
	if err != nil {
		return err
	}
	res.DefaultLeaseTTL = fmt.Sprint(mco.DefaultLeaseTTL)
	res.MaximumLeaseTTL = fmt.Sprint(mco.MaxLeaseTTL)
	res.ForceNoCache = fmt.Sprint(mco.ForceNoCache)

	return nil
}

func (res *vaultMountResource) doMount() error {
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
	err := res.client.Sys().Mount(res.Path, &mri)
	if err != nil {
		return err
	}

	mco, err := res.client.Sys().MountConfig(res.Path)
	if err != nil {
		return err
	}
	res.DefaultLeaseTTL = fmt.Sprint(mco.DefaultLeaseTTL)
	res.MaximumLeaseTTL = fmt.Sprint(mco.MaxLeaseTTL)
	res.ForceNoCache = fmt.Sprint(mco.ForceNoCache)

	return nil
}

func (res *vaultMountResource) doUnmount() error {
	if res.Path == "" {
		return fmt.Errorf("unspecified `Path`")
	}
	if res.TuneOnly == "true" {
		return fmt.Errorf("`%s` configured as `TuneOnly`", res.Path)
	}
	log.Printf("Vault Mount `%s` - attempting to unmount", res.Path)
	return res.client.Sys().Unmount(res.Path)
}
