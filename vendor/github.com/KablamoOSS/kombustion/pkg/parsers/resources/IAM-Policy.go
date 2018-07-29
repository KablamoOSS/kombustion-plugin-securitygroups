package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// IAMPolicy Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html
type IAMPolicy struct {
	Type       string              `yaml:"Type"`
	Properties IAMPolicyProperties `yaml:"Properties"`
	Condition  interface{}         `yaml:"Condition,omitempty"`
	Metadata   interface{}         `yaml:"Metadata,omitempty"`
	DependsOn  interface{}         `yaml:"DependsOn,omitempty"`
}

// IAMPolicy Properties
type IAMPolicyProperties struct {
	PolicyDocument interface{} `yaml:"PolicyDocument"`
	PolicyName     interface{} `yaml:"PolicyName"`
	Groups         interface{} `yaml:"Groups,omitempty"`
	Roles          interface{} `yaml:"Roles,omitempty"`
	Users          interface{} `yaml:"Users,omitempty"`
}

// NewIAMPolicy constructor creates a new IAMPolicy
func NewIAMPolicy(properties IAMPolicyProperties, deps ...interface{}) IAMPolicy {
	return IAMPolicy{
		Type:       "AWS::IAM::Policy",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseIAMPolicy parses IAMPolicy
func ParseIAMPolicy(
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
	var resource IAMPolicy
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

// ParseIAMPolicy validator
func (resource IAMPolicy) Validate() []error {
	return resource.Properties.Validate()
}

// ParseIAMPolicyProperties validator
func (resource IAMPolicyProperties) Validate() []error {
	errors := []error{}
	if resource.PolicyDocument == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'PolicyDocument'"))
	}
	if resource.PolicyName == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'PolicyName'"))
	}
	return errors
}
