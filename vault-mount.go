package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

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
	TokenParameter string `json:",omitempty"`

	Type     string `json:",omitempty"`
	Path     string `json:",omitempty"`
	TuneOnly string `json:",omitempty"`

	DefaultLeaseTTL string `json:",omitempty"`
	MaximumLeaseTTL string `json:",omitempty"`
	ForceNoCache    string `json:",omitempty"`
}

// Create is invoked when the resource is created.
func (res *VaultMountResource) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := customresource.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid
	return res.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (res *VaultMountResource) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := evt.PhysicalResourceID

	vconfig := vaultapi.DefaultConfig()
	if err := vconfig.ReadEnvironment(); err != nil {
		return rid, nil, err
	}

	vclient, err := vaultapi.NewClient(vconfig)
	if err != nil {
		return rid, nil, err
	}

	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return rid, nil, err
	}

	if res.Type == "" {
		// return rid, nil, errors.New("missing required resource property `Type`")
	}

	if res.Path == "" {
		res.Path = res.Type
	}

	if res.TokenParameter == "" {
		return rid, nil, errors.New("missing required resource property `TokenParameter`")
	}

	token, _, err := getParameter(res.TokenParameter)
	if err != nil {
		return rid, nil, err
	}
	vclient.SetToken(token)

	mci := vaultapi.MountConfigInput{
		DefaultLeaseTTL: res.DefaultLeaseTTL,
		MaxLeaseTTL:     res.MaximumLeaseTTL,
	}
	mci.ForceNoCache, _ = strconv.ParseBool(res.ForceNoCache)
	res.ForceNoCache = fmt.Sprint(mci.ForceNoCache)
	if err = vclient.Sys().TuneMount(res.Path, mci); err != nil {
		return rid, nil, err
	}
	mco, err := vclient.Sys().MountConfig(res.Path)
	if err != nil {
		return rid, nil, err
	}
	res.DefaultLeaseTTL = fmt.Sprint(mco.DefaultLeaseTTL)
	res.MaximumLeaseTTL = fmt.Sprint(mco.MaxLeaseTTL)
	res.ForceNoCache = fmt.Sprint(mco.ForceNoCache)
	return rid, res, nil
}

// Delete is invoked when the resource is deleted.
func (res *VaultMountResource) Delete(*cloudformation.Event, *lambdaruntime.Context) error {
	return nil
}
