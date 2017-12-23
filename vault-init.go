package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/eawsy/aws-cloudformation-go-customres/service/cloudformation/customres"
	"github.com/eawsy/aws-lambda-go-core/service/lambda/runtime"
	cloudformation "github.com/eawsy/aws-lambda-go-event/service/lambda/runtime/event/cloudformationevt"
	vault "github.com/hashicorp/vault/api"
)

func init() {
	customres.Register("VaultInit", new(VaultInit))
}

// VaultInit represents `vault init` CloudFormation resource.
type VaultInit struct{}

// VaultInitProperties encapsulates the Properties specified on the custom resource.
type VaultInitProperties struct {
	VaultScheme                   string `json:"VaultScheme"`
	VaultGroup                    string `json:"VaultGroup"`
	VaultPort                     string `json:"VaultPort"`
	VaultRootTokenEncryptionKey   string `json:"VaultRootTokenEncryptionKey"`
	VaultSecretShareEncryptionKey string `json:"VaultSecretShareEncryptionKey"`
}

// Create is invoked when the resource is created.
func (r *VaultInit) Create(evt *cloudformation.Event, ctx *runtime.Context) (string, interface{}, error) {
	rid := customres.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid
	return r.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (r *VaultInit) Update(evt *cloudformation.Event, ctx *runtime.Context) (string, interface{}, error) {
	var (
		vscheme   = "http"
		vgroup    string
		vhost     string
		vport     = "8200"
		venctoken string
		vencshare string
	)

	aws := session.Must(session.NewSession())
	rid := evt.PhysicalResourceID

	p := map[string]string{}
	if err := json.Unmarshal(evt.ResourceProperties, &p); err != nil {
		return rid, nil, err
	}

	if v, ok := p["VaultGroup"]; ok {
		vgroup = v
	}
	if vgroup == "" {
		return rid, nil, errors.New("missing required resource property `VaultGroup`")
	}

	if v, ok := p["VaultScheme"]; ok {
		vscheme = v
	}

	if v, ok := p["VaultPort"]; ok {
		vport = v
	}

	if v, ok := p["VaultRootTokenEncryptionKey"]; ok {
		venctoken = v
	}

	if v, ok := p["VaultSecretShareEncryptionKey"]; ok {
		vencshare = v
	}

	vhost, err := instancePrivateIP(aws, vgroup)
	if err != nil {
		return rid, nil, err
	}

	vconfig := vault.DefaultConfig()
	if err := vconfig.ReadEnvironment(); err != nil {
		return rid, nil, err
	}
	vconfig.Address = fmt.Sprintf("%s://%s:%s", vscheme, vhost, vport)

	vclient, err := vault.NewClient(vconfig)
	if err != nil {
		return rid, nil, err
	}

	stcknm := strings.Split(evt.StackID, "/")[1]
	ssname := fmt.Sprintf("/%s/%s/Secret/0", stcknm, rid)
	rtname := fmt.Sprintf("/%s/%s/Token/Root", stcknm, rid)

	vhealth, err := vclient.Sys().Health()
	for i := 0; err != nil && i < 10; i++ {
		log.Printf("sleeping prior to retry, because: %s", err)
		time.Sleep(5 * time.Second)
		vhealth, err = vclient.Sys().Health()
	}
	if err != nil {
		return rid, nil, err
	}

	if vhealth.Initialized {
		return rid, map[string]string{
			"SecretShareParameter": ssname,
			"RootTokenParameter":   rtname,
		}, nil
	}

	vinitreq := vault.InitRequest{
		SecretShares:    1,
		SecretThreshold: 1,
	}

	log.Printf("VaultInit Request: %+v", vinitreq)
	vinitres, err := vclient.Sys().Init(&vinitreq)
	// DO NOT LOG THE RESPONSE
	if err != nil {
		log.Printf("VaultInit Error: %s", err)
		return rid, nil, err
	}

	ssopts := &parameterOptions{
		Description:   "Vault Unseal Key",
		EncryptionKey: vencshare,
	}
	if _, err = ssmPutParameter(aws, ssopts, ssname, vinitres.Keys[0]); err != nil {
		log.Printf("PutParameter Error: %s", err)
		return rid, nil, err
	}

	rtopts := &parameterOptions{
		Description:   "Vault Root Token",
		EncryptionKey: venctoken,
	}
	if _, err = ssmPutParameter(aws, rtopts, rtname, vinitres.RootToken); err != nil {
		log.Printf("PutParameter Error: %s", err)
		return rid, nil, err
	}

	return rid, map[string]string{
		"SecretShareParameter": ssname,
		"RootTokenParameter":   rtname,
	}, nil
}

// Delete is invoked when the resource is deleted.
func (r *VaultInit) Delete(*cloudformation.Event, *runtime.Context) error {
	return nil
}

func instancePrivateIP(ses *session.Session, group string) (string, error) {
	autoscalingClient := autoscaling.New(ses)
	ec2Client := ec2.New(ses)

	dgi := &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []*string{&group},
	}
	dgo, err := autoscalingClient.DescribeAutoScalingGroups(dgi)
	if err != nil {
		return "", err
	}
	if len(dgo.AutoScalingGroups) == 0 {
		return "", fmt.Errorf("autoscaling group `%s` not found", group)
	}
	if len(dgo.AutoScalingGroups[0].Instances) == 0 {
		return "", fmt.Errorf("autoscaling group `%s` has no instances", group)
	}

	iid := dgo.AutoScalingGroups[0].Instances[0].InstanceId
	dii := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{iid},
	}
	dio, err := ec2Client.DescribeInstances(dii)
	if err != nil {
		return "", err
	}
	if len(dio.Reservations) == 0 {
		return "", fmt.Errorf("ec2 instance `%s` not found", *iid)
	}

	iip := dio.Reservations[0].Instances[0].PrivateIpAddress
	return *iip, nil
}

type parameterOptions struct {
	Type           string
	Description    string
	Overwrite      bool
	AllowedPattern string
	EncryptionKey  string
}

func ssmPutParameter(ses *session.Session, options *parameterOptions, name, value string) (int64, error) {
	if options == nil {
		options = &parameterOptions{}
	}

	if options.EncryptionKey != "" {
		options.Type = ssm.ParameterTypeSecureString
	}

	if options.Type == "" {
		options.Type = ssm.ParameterTypeString
	}

	ppi := &ssm.PutParameterInput{}
	if options.EncryptionKey != "" {
		ppi.SetKeyId(options.EncryptionKey)
	}
	if options.Description != "" {
		ppi.SetDescription(options.Description)
	}
	if options.AllowedPattern != "" {
		ppi.SetAllowedPattern(options.AllowedPattern)
	}
	ppi.SetType(options.Type)
	ppi.SetOverwrite(options.Overwrite)
	ppi.SetName(name)
	ppi.SetValue(value)

	ppo, err := ssm.New(ses).PutParameter(ppi)
	if err != nil {
		return 0, err
	}
	return *ppo.Version, nil
}
