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
	customresource.Register("VaultAudit", new(vaultAuditHandler))
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

type vaultAuditHandler struct{}
type vaultAuditResource struct {
	vaultResource `json:"-"`

	Type        string            `json:",omitempty"`
	Path        string            `json:",omitempty"`
	Local       string            `json:",omitempty"`
	Options     map[string]string `json:",omitempty"`
	Description string            `json:",omitempty"`
	Disable     string            `json:",omitempty"`
}

func (h *vaultAuditHandler) resource(evt *cloudformation.Event) (string, *vaultAuditResource, error) {
	rid := resourceID(evt)
	res := &vaultAuditResource{}

	if err := json.Unmarshal(evt.ResourceProperties, res); err != nil {
		return rid, nil, err
	}

	disable, err := strconv.ParseBool(res.Disable)
	if err != nil {
		log.Printf("failed to parse `Disable`: %v", err)
	}
	res.Disable = fmt.Sprint(disable)

	local, err := strconv.ParseBool(res.Local)
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

	return rid, res, res.initWithTokenParameterOverride()
}

// Create is invoked when the resource is created.
func (h *vaultAuditHandler) Create(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	return h.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (h *vaultAuditHandler) Update(evt *cloudformation.Event, ctx *lambdaruntime.Context) (string, interface{}, error) {
	rid, res, err := h.resource(evt)
	if err != nil {
		return rid, nil, err
	}

	if res.Disable == "true" {
		log.Printf("Vault Audit `%s` disable", res.Path)
		return rid, res, res.client.Sys().DisableAudit(res.Path)
	}

	audits, err := res.client.Sys().ListAudit()
	if err != nil {
		return rid, nil, err
	}

	for _, audit := range audits {
		if audit.Path == res.Path {
			res.Type = audit.Type
			res.Local = fmt.Sprint(audit.Local)
			res.Options = audit.Options
			res.Description = audit.Description
			log.Printf("Vault Audit `%s` exists: Type:%s, Local:%s, Description:%s", res.Path, res.Type, res.Local, res.Description)
			return rid, res, nil
		}
	}

	opts := vaultapi.EnableAuditOptions{
		Type:        res.Type,
		Description: res.Description,
		Options:     res.Options,
		Local:       res.Local == "true",
	}

	log.Printf("Vault Audit `%s` enable: Type:%s, Local:%s, Description:%s", res.Path, res.Type, res.Local, res.Description)
	return rid, res, res.client.Sys().EnableAuditWithOptions(res.Path, &opts)
}

// Delete is invoked when the resource is deleted.
func (h *vaultAuditHandler) Delete(evt *cloudformation.Event, ctx *lambdaruntime.Context) error {
	_, res, err := h.resource(evt)

	if err == nil {
		res.client.SetMaxRetries(1)
		res.client.SetClientTimeout(30 * time.Second)
		err = res.client.Sys().DisableAudit(res.Path)
	}

	if err != nil {
		log.Printf("skipping disablement of Vault Audit backend: %v", err)
	}

	return nil
}
