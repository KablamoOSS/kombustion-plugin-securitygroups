package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// EC2VPC Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc.html
type EC2VPC struct {
	Type       string           `yaml:"Type"`
	Properties EC2VPCProperties `yaml:"Properties"`
	Condition  interface{}      `yaml:"Condition,omitempty"`
	Metadata   interface{}      `yaml:"Metadata,omitempty"`
	DependsOn  interface{}      `yaml:"DependsOn,omitempty"`
}

// EC2VPC Properties
type EC2VPCProperties struct {
	CidrBlock          interface{} `yaml:"CidrBlock"`
	EnableDnsHostnames interface{} `yaml:"EnableDnsHostnames,omitempty"`
	EnableDnsSupport   interface{} `yaml:"EnableDnsSupport,omitempty"`
	InstanceTenancy    interface{} `yaml:"InstanceTenancy,omitempty"`
	Tags               interface{} `yaml:"Tags,omitempty"`
}

// NewEC2VPC constructor creates a new EC2VPC
func NewEC2VPC(properties EC2VPCProperties, deps ...interface{}) EC2VPC {
	return EC2VPC{
		Type:       "AWS::EC2::VPC",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseEC2VPC parses EC2VPC
func ParseEC2VPC(
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
	var resource EC2VPC
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

// ParseEC2VPC validator
func (resource EC2VPC) Validate() []error {
	return resource.Properties.Validate()
}

// ParseEC2VPCProperties validator
func (resource EC2VPCProperties) Validate() []error {
	errors := []error{}
	if resource.CidrBlock == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'CidrBlock'"))
	}
	return errors
}
