package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ssm"
)

var (
	autoscalingSubsystem *autoscaling.AutoScaling
	elasticComputeCloud  *ec2.EC2
	simpleSystemsManager *ssm.SSM
)

func init() {
	awsSession := session.Must(session.NewSession())

	autoscalingSubsystem = autoscaling.New(awsSession)
	elasticComputeCloud = ec2.New(awsSession)
	simpleSystemsManager = ssm.New(awsSession)
}

// returns ip addresses of instances in the "running" state from the first page of results
func listInstanceAddressesInGroup(group string) ([]string, error) {
	instanceAddresses := []string{}

	dgi := &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []*string{&group},
	}
	dgo, err := autoscalingSubsystem.DescribeAutoScalingGroups(dgi)
	if err != nil {
		return instanceAddresses, err
	}
	if len(dgo.AutoScalingGroups) == 0 {
		return instanceAddresses, fmt.Errorf("autoscaling group `%s` not found", group)
	}
	if len(dgo.AutoScalingGroups[0].Instances) == 0 {
		return instanceAddresses, fmt.Errorf("autoscaling group `%s` has no instances", group)
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
	dio, err := elasticComputeCloud.DescribeInstances(dii)
	if err != nil {
		return instanceAddresses, err
	}
	if dio.Reservations != nil {
		for _, r := range dio.Reservations {
			for _, i := range r.Instances {
				instanceAddresses = append(instanceAddresses, *i.PrivateIpAddress)
			}
		}
	}

	return instanceAddresses, nil
}

type parameterOptions struct {
	Type           string
	Description    string
	Overwrite      bool
	AllowedPattern string
	EncryptionKey  string
}

func getParameter(name string) (string, int64, error) {
	gpi := &ssm.GetParameterInput{}
	gpi.SetName(name)
	gpi.SetWithDecryption(true)
	gpo, err := simpleSystemsManager.GetParameter(gpi)
	if err != nil {
		return "", 0, err
	}
	if gpo.Parameter == nil {
		return "", 0, fmt.Errorf("parameter not found: %s", name)
	}
	return *gpo.Parameter.Value, *gpo.Parameter.Version, nil
}

func putParameter(options *parameterOptions, name, value string) (int64, error) {
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

	ppo, err := simpleSystemsManager.PutParameter(ppi)
	if err != nil {
		return 0, err
	}
	return *ppo.Version, nil
}
