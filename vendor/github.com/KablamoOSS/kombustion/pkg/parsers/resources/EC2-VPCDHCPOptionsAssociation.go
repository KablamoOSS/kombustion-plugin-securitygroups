package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// EC2VPCDHCPOptionsAssociation Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc-dhcp-options-assoc.html
type EC2VPCDHCPOptionsAssociation struct {
	Type       string                                 `yaml:"Type"`
	Properties EC2VPCDHCPOptionsAssociationProperties `yaml:"Properties"`
	Condition  interface{}                            `yaml:"Condition,omitempty"`
	Metadata   interface{}                            `yaml:"Metadata,omitempty"`
	DependsOn  interface{}                            `yaml:"DependsOn,omitempty"`
}

// EC2VPCDHCPOptionsAssociation Properties
type EC2VPCDHCPOptionsAssociationProperties struct {
	DhcpOptionsId interface{} `yaml:"DhcpOptionsId"`
	VpcId         interface{} `yaml:"VpcId"`
}

// NewEC2VPCDHCPOptionsAssociation constructor creates a new EC2VPCDHCPOptionsAssociation
func NewEC2VPCDHCPOptionsAssociation(properties EC2VPCDHCPOptionsAssociationProperties, deps ...interface{}) EC2VPCDHCPOptionsAssociation {
	return EC2VPCDHCPOptionsAssociation{
		Type:       "AWS::EC2::VPCDHCPOptionsAssociation",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseEC2VPCDHCPOptionsAssociation parses EC2VPCDHCPOptionsAssociation
func ParseEC2VPCDHCPOptionsAssociation(
	name string,
	data string,
) (
	source string,
	conditions types.TemplateObject,
	metadata types.TemplateObject,
	mappings types.TemplateObject,
	outputs types.TemplateObject,
	parameters types.TemplateObject,
	resources types.TemplateObject,
	transform types.TemplateObject,
	errors []error,
) {
	source = "kombustion-core-resources"
	var resource EC2VPCDHCPOptionsAssociation
	err := yaml.Unmarshal([]byte(data), &resource)

	if err != nil {
		errors = append(errors, err)
		return
	}

	if validateErrs := resource.Properties.Validate(); len(errors) > 0 {
		errors = append(errors, validateErrs...)
		return
	}

	resources = types.TemplateObject{name: resource}

	return
}

// ParseEC2VPCDHCPOptionsAssociation validator
func (resource EC2VPCDHCPOptionsAssociation) Validate() []error {
	return resource.Properties.Validate()
}

// ParseEC2VPCDHCPOptionsAssociationProperties validator
func (resource EC2VPCDHCPOptionsAssociationProperties) Validate() []error {
	errors := []error{}
	if resource.DhcpOptionsId == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'DhcpOptionsId'"))
	}
	if resource.VpcId == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'VpcId'"))
	}
	return errors
}
