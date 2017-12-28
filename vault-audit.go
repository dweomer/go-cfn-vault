package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	customresource "github.com/eawsy/aws-cloudformation-go-customres/service/cloudformation/customres"
	lambdaruntime "github.com/eawsy/aws-lambda-go-core/service/lambda/runtime"
	cloudformation "github.com/eawsy/aws-lambda-go-event/service/lambda/runtime/event/cloudformationevt"
	vaultapi "github.com/hashicorp/vault/api"
)

func init() {
	customresource.Register("VaultAudit", new(VaultAuditResource))
}

const (
	auditTypeFile = "file"
)

var (
	auditDefaultType    = auditTypeFile
	auditDefaultOptions = map[string]string{
		"file_path": "/vault/logs/audit.log",
	}
)

// VaultAuditResource represents `vault audit enable/disable` CloudFormation resource.
type VaultAuditResource struct {
	TokenParameter string `json:",omitempty"`

	Type        string            `json:",omitempty"`
	Path        string            `json:",omitempty"`
	Local       string            `json:",omitempty"`
	Options     map[string]string `json:",omitempty"`
	Description string            `json:",omitempty"`
	Disable     string            `json:",omitempty"`
}

// Create is invoked when the resource is created.
func (res *VaultAuditResource) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid := customresource.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid
	return res.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (res *VaultAuditResource) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
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

	if res.TokenParameter == "" {
		return rid, nil, errors.New("missing required resource property `TokenParameter`")
	}

	if res.Type == "" {
		res.Type = auditDefaultType
	}

	if res.Path == "" {
		res.Path = res.Type
	}

	if !strings.HasSuffix(res.Path, "/") {
		res.Path += "/"
	}

	if res.Type == auditTypeFile && len(res.Options) == 0 {
		for k, v := range auditDefaultOptions {
			res.Options[k] = v
		}
	}

	token, _, err := getParameter(res.TokenParameter)
	if err != nil {
		return rid, nil, err
	}
	vclient.SetToken(token)

	if disable, _ := strconv.ParseBool(res.Disable); disable {
		log.Printf("Vault Audit Disable - Path:%s", res.Path)
		return rid, res, vclient.Sys().DisableAudit(res.Path)
	}

	audits, err := vclient.Sys().ListAudit()
	if err != nil {
		return rid, nil, err
	}

	for _, audit := range audits {
		if audit.Path == res.Path {
			res.Type = audit.Type
			res.Local = fmt.Sprintf("%t", audit.Local)
			res.Options = audit.Options
			res.Description = audit.Description
			log.Printf("Vault Audit (Found) - Path:%s, Type:%s, Local:%s, Description:%s", res.Path, res.Type, res.Local, res.Description)
			return rid, res, nil
		}
	}

	opts := vaultapi.EnableAuditOptions{
		Type:        res.Type,
		Description: res.Description,
		Options:     res.Options,
	}
	opts.Local, _ = strconv.ParseBool(res.Local)
	res.Local = fmt.Sprint(opts.Local)
	log.Printf("Vault Audit Enable - Path:%s, Type:%s, Local:%s, Description:%s", res.Path, res.Type, res.Local, res.Description)
	return rid, res, vclient.Sys().EnableAuditWithOptions(res.Path, &opts)
}

// Delete is invoked when the resource is deleted.
func (res *VaultAuditResource) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	vconfig := vaultapi.DefaultConfig()
	if err := vconfig.ReadEnvironment(); err != nil {
		log.Printf("skipping delete of Vault Audit backend: %v", err)
		return nil
	}

	vclient, err := vaultapi.NewClient(vconfig)
	if err != nil {
		log.Printf("skipping delete of Vault Audit backend: %v", err)
		return nil
	}

	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		log.Printf("skipping delete of Vault Audit backend: %v", err)
		return nil
	}

	if res.Type == "" {
		res.Type = auditDefaultType
	}

	if res.Path == "" {
		res.Path = res.Type
	}

	if !strings.HasSuffix(res.Path, "/") {
		res.Path += "/"
	}

	if res.TokenParameter == "" {
		log.Printf("skipping delete of Vault Audit backend at `%s`: %v", res.Path, "missing property `TokenParameter`")
	}

	if res.Type == auditTypeFile && len(res.Options) == 0 {
		for k, v := range auditDefaultOptions {
			res.Options[k] = v
		}
	}

	token, _, err := getParameter(res.TokenParameter)
	if err != nil {
		log.Printf("skipping delete of Vault Audit backend at `%s`: %v", res.Path, err)
	}
	vclient.SetToken(token)

	log.Printf("Vault Audit Disable - Path:%s", res.Path)
	return vclient.Sys().DisableAudit(res.Path)
}
