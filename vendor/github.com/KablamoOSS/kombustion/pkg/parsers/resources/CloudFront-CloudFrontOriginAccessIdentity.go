package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/pkg/parsers/properties"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// CloudFrontCloudFrontOriginAccessIdentity Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-cloudfrontoriginaccessidentity.html
type CloudFrontCloudFrontOriginAccessIdentity struct {
	Type       string                                             `yaml:"Type"`
	Properties CloudFrontCloudFrontOriginAccessIdentityProperties `yaml:"Properties"`
	Condition  interface{}                                        `yaml:"Condition,omitempty"`
	Metadata   interface{}                                        `yaml:"Metadata,omitempty"`
	DependsOn  interface{}                                        `yaml:"DependsOn,omitempty"`
}

// CloudFrontCloudFrontOriginAccessIdentity Properties
type CloudFrontCloudFrontOriginAccessIdentityProperties struct {
	CloudFrontOriginAccessIdentityConfig *properties.CloudFrontOriginAccessIdentityCloudFrontOriginAccessIdentityConfig `yaml:"CloudFrontOriginAccessIdentityConfig"`
}

// NewCloudFrontCloudFrontOriginAccessIdentity constructor creates a new CloudFrontCloudFrontOriginAccessIdentity
func NewCloudFrontCloudFrontOriginAccessIdentity(properties CloudFrontCloudFrontOriginAccessIdentityProperties, deps ...interface{}) CloudFrontCloudFrontOriginAccessIdentity {
	return CloudFrontCloudFrontOriginAccessIdentity{
		Type:       "AWS::CloudFront::CloudFrontOriginAccessIdentity",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseCloudFrontCloudFrontOriginAccessIdentity parses CloudFrontCloudFrontOriginAccessIdentity
func ParseCloudFrontCloudFrontOriginAccessIdentity(
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
	var resource CloudFrontCloudFrontOriginAccessIdentity
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

// ParseCloudFrontCloudFrontOriginAccessIdentity validator
func (resource CloudFrontCloudFrontOriginAccessIdentity) Validate() []error {
	return resource.Properties.Validate()
}

// ParseCloudFrontCloudFrontOriginAccessIdentityProperties validator
func (resource CloudFrontCloudFrontOriginAccessIdentityProperties) Validate() []error {
	errors := []error{}
	if resource.CloudFrontOriginAccessIdentityConfig == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'CloudFrontOriginAccessIdentityConfig'"))
	} else {
		errors = append(errors, resource.CloudFrontOriginAccessIdentityConfig.Validate()...)
	}
	return errors
}
