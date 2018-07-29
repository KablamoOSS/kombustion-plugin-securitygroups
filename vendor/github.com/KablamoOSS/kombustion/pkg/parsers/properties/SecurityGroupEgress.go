package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// SecurityGroupEgress Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-rule.html
type SecurityGroupEgress struct {
	CidrIp                     interface{} `yaml:"CidrIp,omitempty"`
	CidrIpv6                   interface{} `yaml:"CidrIpv6,omitempty"`
	Description                interface{} `yaml:"Description,omitempty"`
	DestinationPrefixListId    interface{} `yaml:"DestinationPrefixListId,omitempty"`
	DestinationSecurityGroupId interface{} `yaml:"DestinationSecurityGroupId,omitempty"`
	FromPort                   interface{} `yaml:"FromPort,omitempty"`
	IpProtocol                 interface{} `yaml:"IpProtocol"`
	ToPort                     interface{} `yaml:"ToPort,omitempty"`
}

// SecurityGroupEgress validation
func (resource SecurityGroupEgress) Validate() []error {
	errors := []error{}

	if resource.IpProtocol == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'IpProtocol'"))
	}
	return errors
}