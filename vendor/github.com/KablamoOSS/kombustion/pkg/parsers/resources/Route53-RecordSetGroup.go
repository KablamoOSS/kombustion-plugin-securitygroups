package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// Route53RecordSetGroup Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-recordsetgroup.html
type Route53RecordSetGroup struct {
	Type       string                          `yaml:"Type"`
	Properties Route53RecordSetGroupProperties `yaml:"Properties"`
	Condition  interface{}                     `yaml:"Condition,omitempty"`
	Metadata   interface{}                     `yaml:"Metadata,omitempty"`
	DependsOn  interface{}                     `yaml:"DependsOn,omitempty"`
}

// Route53RecordSetGroup Properties
type Route53RecordSetGroupProperties struct {
	Comment        interface{} `yaml:"Comment,omitempty"`
	HostedZoneId   interface{} `yaml:"HostedZoneId,omitempty"`
	HostedZoneName interface{} `yaml:"HostedZoneName,omitempty"`
	RecordSets     interface{} `yaml:"RecordSets,omitempty"`
}

// NewRoute53RecordSetGroup constructor creates a new Route53RecordSetGroup
func NewRoute53RecordSetGroup(properties Route53RecordSetGroupProperties, deps ...interface{}) Route53RecordSetGroup {
	return Route53RecordSetGroup{
		Type:       "AWS::Route53::RecordSetGroup",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseRoute53RecordSetGroup parses Route53RecordSetGroup
func ParseRoute53RecordSetGroup(
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
	var resource Route53RecordSetGroup
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

// ParseRoute53RecordSetGroup validator
func (resource Route53RecordSetGroup) Validate() []error {
	return resource.Properties.Validate()
}

// ParseRoute53RecordSetGroupProperties validator
func (resource Route53RecordSetGroupProperties) Validate() []error {
	errors := []error{}
	return errors
}
