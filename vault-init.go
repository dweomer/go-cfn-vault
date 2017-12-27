package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
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
	customres.Register("Init", new(InitResource))
}

const (
	defaultScheme = "http"
	defaultPort   = "8200"
)

// InitResource represents `vault init` CloudFormation resource.
type InitResource struct {
	ServerScheme string `json:",omitempty"`
	ServerGroup  string `json:",omitempty"`
	ServerPort   string `json:",omitempty"`

	RootTokenEncryptionKey string `json:",omitempty"`
	RootTokenParameterName string `json:",omitempty"`

	SecretShareEncryptionKey string `json:",omitempty"`
	SecretShareParameterName string `json:",omitempty"`

	ShouldUnseal string `json:",omitempty"`
}

// Create is invoked when the resource is created.
func (r *InitResource) Create(evt *cloudformation.Event, ctx *runtime.Context) (string, interface{}, error) {
	rid := customres.NewPhysicalResourceID(evt)
	evt.PhysicalResourceID = rid
	return r.Update(evt, ctx)
}

// Update is invoked when the resource is updated.
func (r *InitResource) Update(evt *cloudformation.Event, ctx *runtime.Context) (string, interface{}, error) {
	aws := session.Must(session.NewSession())
	rid := evt.PhysicalResourceID

	if err := json.Unmarshal(evt.ResourceProperties, r); err != nil {
		return rid, nil, err
	}

	if r.ServerScheme == "" {
		r.ServerScheme = defaultScheme
	}

	if r.ServerGroup == "" {
		return rid, nil, errors.New("missing required resource property `ServerGroup`")
	}

	if r.ServerPort == "" {
		r.ServerScheme = defaultPort
	}

	stcknm := strings.Split(evt.StackID, "/")[1]

	if r.RootTokenParameterName == "" {
		r.RootTokenParameterName = fmt.Sprintf("/%s/%s", stcknm, "Vault/Token/Root")
	}

	if r.SecretShareParameterName == "" {
		r.SecretShareParameterName = fmt.Sprintf("/%s/%s", stcknm, "Vault/Secret/Unseal-1")
	}

	if r.RootTokenParameterName == r.SecretShareParameterName {
		return rid, nil, errors.New("RootTokenParameterName must be different than SecretShareParameterName")
	}

	vipaddr, err := listInstanceAddressesInGroup(aws, r.ServerGroup)
	if err != nil {
		return rid, nil, err
	}
	if len(vipaddr) == 0 {
		return rid, nil, fmt.Errorf("no suitable instances found in `%s`", r.ServerGroup)
	}

	vconfig := vault.DefaultConfig()
	if err := vconfig.ReadEnvironment(); err != nil {
		return rid, nil, err
	}
	vconfig.Address = fmt.Sprintf("%s://%s:%s", r.ServerScheme, vipaddr[0], r.ServerPort)

	vclient, err := vault.NewClient(vconfig)
	if err != nil {
		return rid, nil, err
	}

	vhealth, err := vclient.Sys().Health()
	for i := 0; err != nil && i < 10; i++ {
		log.Printf("sleeping prior to retry, because: %s", err)
		time.Sleep(5 * time.Second)
		vhealth, err = vclient.Sys().Health()
	}
	if err != nil {
		return rid, nil, err
	}

	response := map[string]string{
		"SecretShareParameter": r.SecretShareParameterName,
		"RootTokenParameter":   r.RootTokenParameterName,
	}

	if !vhealth.Initialized {
		vinitreq := vault.InitRequest{
			SecretShares:    1,
			SecretThreshold: 1,
		}

		log.Printf("Vault Init Request: %+v", vinitreq)
		vinitres, err := vclient.Sys().Init(&vinitreq)
		// DO NOT LOG THE RESPONSE
		if err != nil {
			log.Printf("Vault Init Error: %s", err)
			return rid, nil, err
		}

		ssopts := &parameterOptions{
			Description:   "Vault Unseal Key",
			EncryptionKey: r.SecretShareEncryptionKey,
			Overwrite:     true,
		}
		if _, err = ssmPutParameter(aws, ssopts, r.SecretShareParameterName, vinitres.Keys[0]); err != nil {
			log.Printf("SSM PutParameter Error: %s", err)
			return rid, nil, err
		}

		rtopts := &parameterOptions{
			Description:   "Vault Root Token",
			EncryptionKey: r.RootTokenEncryptionKey,
			Overwrite:     true,
		}
		if _, err = ssmPutParameter(aws, rtopts, r.RootTokenParameterName, vinitres.RootToken); err != nil {
			log.Printf("SSM PutParameter Error: %s", err)
			return rid, nil, err
		}

		if unseal, err := strconv.ParseBool(r.ShouldUnseal); vhealth.Sealed && unseal && err == nil {
			vss, err := vclient.Sys().Unseal(vinitres.Keys[0])
			if err != nil {
				log.Printf("Vault Unseal Error: %s", err)
			}
			log.Printf("Vault Seal Status: %+v", vss)
		}
	}

	return rid, response, nil
}

// Delete is invoked when the resource is deleted.
func (r *InitResource) Delete(*cloudformation.Event, *runtime.Context) error {
	return nil
}

func listInstanceAddressesInGroup(ses *session.Session, group string) ([]string, error) {
	autoscalingClient := autoscaling.New(ses)
	ec2Client := ec2.New(ses)

	iad := []string{}

	dgi := &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []*string{&group},
	}
	dgo, err := autoscalingClient.DescribeAutoScalingGroups(dgi)
	if err != nil {
		return iad, err
	}
	if len(dgo.AutoScalingGroups) == 0 {
		return iad, fmt.Errorf("autoscaling group `%s` not found", group)
	}
	if len(dgo.AutoScalingGroups[0].Instances) == 0 {
		return iad, fmt.Errorf("autoscaling group `%s` has no instances", group)
	}

	iid := []*string{}
	for _, i := range dgo.AutoScalingGroups[0].Instances {
		iid = append(iid, i.InstanceId)
	}
	isf := "instance-state-name"
	isn := ec2.InstanceStateNameRunning
	dii := &ec2.DescribeInstancesInput{
		InstanceIds: iid,
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   &isf,
				Values: []*string{&isn},
			},
		},
	}
	dio, err := ec2Client.DescribeInstances(dii)
	if err != nil {
		return iad, err
	}
	for _, i := range dio.Reservations[0].Instances {
		iad = append(iad, *i.PrivateIpAddress)
	}

	return iad, nil
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
