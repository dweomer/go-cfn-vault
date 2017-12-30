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
	customresource.Register("VaultAudit", new(VaultAuditResource))
}

const (
	auditTypeFile = "file"
)

var (
	auditDefaultType        = auditTypeFile
	auditDefaultFileOptions = map[string]string{
		"file_path": "/var/log/vault/audit.log",
	}
)

// VaultAuditResource represents `vault audit enable/disable` CloudFormation resource.
type VaultAuditResource struct {
	Type        string            `json:",omitempty"`
	Path        string            `json:",omitempty"`
	Local       string            `json:",omitempty"`
	Options     map[string]string `json:",omitempty"`
	Description string            `json:",omitempty"`
	Disable     string            `json:",omitempty"`
}

func (res *VaultAuditResource) configure(evt *cloudformation.Event) (disable bool, local bool, err error) {
	readVaultTokenParameter()

	if err = json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return false, false, err
	}

	disable, err = strconv.ParseBool(res.Disable)
	if err != nil {
		log.Printf("failed to parse `Disable`: %v", err)
	}
	res.Disable = fmt.Sprint(disable)

	local, err = strconv.ParseBool(res.Local)
	if err != nil {
		log.Printf("failed to parse `Local`: %v", err)
	}
	res.Local = fmt.Sprint(local)

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
		for k, v := range auditDefaultFileOptions {
			res.Options[k] = v
		}
	}

	return disable, local, nil
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

	disable, local, err := res.configure(evt)
	if err != nil {
		return rid, nil, err
	}

	if disable {
		log.Printf("Vault Audit Disable - Path:%s", res.Path)
		return rid, res, vault.Sys().DisableAudit(res.Path)
	}

	audits, err := vault.Sys().ListAudit()
	if err != nil {
		return rid, nil, err
	}

	for _, audit := range audits {
		if audit.Path == res.Path {
			res.Type = audit.Type
			res.Local = fmt.Sprint(audit.Local)
			res.Options = audit.Options
			res.Description = audit.Description
			log.Printf("Vault Audit Exists - Path:%s, Type:%s, Local:%s, Description:%s", res.Path, res.Type, res.Local, res.Description)
			return rid, res, nil
		}
	}

	opts := vaultapi.EnableAuditOptions{
		Type:        res.Type,
		Description: res.Description,
		Options:     res.Options,
		Local:       local,
	}

	log.Printf("Vault Audit Enable - Path:%s, Type:%s, Local:%s, Description:%s", res.Path, res.Type, res.Local, res.Description)
	return rid, res, vault.Sys().EnableAuditWithOptions(res.Path, &opts)
}

// Delete is invoked when the resource is deleted.
func (res *VaultAuditResource) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	_, _, err := res.configure(evt)
	if err == nil {
		vault.SetMaxRetries(1)
		vault.SetClientTimeout(30 * time.Second)
		err = vault.Sys().DisableAudit(res.Path)
	}

	if err != nil {
		log.Printf("skipping disablement of Vault Audit backend: %v", err)
	}

	return nil
}
