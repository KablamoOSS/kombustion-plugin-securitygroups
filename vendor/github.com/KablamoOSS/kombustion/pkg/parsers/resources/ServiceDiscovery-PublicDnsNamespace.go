package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// ServiceDiscoveryPublicDnsNamespace Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-servicediscovery-publicdnsnamespace.html
type ServiceDiscoveryPublicDnsNamespace struct {
	Type       string                                       `yaml:"Type"`
	Properties ServiceDiscoveryPublicDnsNamespaceProperties `yaml:"Properties"`
	Condition  interface{}                                  `yaml:"Condition,omitempty"`
	Metadata   interface{}                                  `yaml:"Metadata,omitempty"`
	DependsOn  interface{}                                  `yaml:"DependsOn,omitempty"`
}

// ServiceDiscoveryPublicDnsNamespace Properties
type ServiceDiscoveryPublicDnsNamespaceProperties struct {
	Description interface{} `yaml:"Description,omitempty"`
	Name        interface{} `yaml:"Name"`
}

// NewServiceDiscoveryPublicDnsNamespace constructor creates a new ServiceDiscoveryPublicDnsNamespace
func NewServiceDiscoveryPublicDnsNamespace(properties ServiceDiscoveryPublicDnsNamespaceProperties, deps ...interface{}) ServiceDiscoveryPublicDnsNamespace {
	return ServiceDiscoveryPublicDnsNamespace{
		Type:       "AWS::ServiceDiscovery::PublicDnsNamespace",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseServiceDiscoveryPublicDnsNamespace parses ServiceDiscoveryPublicDnsNamespace
func ParseServiceDiscoveryPublicDnsNamespace(
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
	var resource ServiceDiscoveryPublicDnsNamespace
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

// ParseServiceDiscoveryPublicDnsNamespace validator
func (resource ServiceDiscoveryPublicDnsNamespace) Validate() []error {
	return resource.Properties.Validate()
}

// ParseServiceDiscoveryPublicDnsNamespaceProperties validator
func (resource ServiceDiscoveryPublicDnsNamespaceProperties) Validate() []error {
	errors := []error{}
	if resource.Name == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Name'"))
	}
	return errors
}
