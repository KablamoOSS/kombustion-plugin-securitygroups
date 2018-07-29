package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/pkg/parsers/properties"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// CloudFrontStreamingDistribution Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-streamingdistribution.html
type CloudFrontStreamingDistribution struct {
	Type       string                                    `yaml:"Type"`
	Properties CloudFrontStreamingDistributionProperties `yaml:"Properties"`
	Condition  interface{}                               `yaml:"Condition,omitempty"`
	Metadata   interface{}                               `yaml:"Metadata,omitempty"`
	DependsOn  interface{}                               `yaml:"DependsOn,omitempty"`
}

// CloudFrontStreamingDistribution Properties
type CloudFrontStreamingDistributionProperties struct {
	StreamingDistributionConfig *properties.StreamingDistributionStreamingDistributionConfig `yaml:"StreamingDistributionConfig"`
	Tags                        interface{}                                                  `yaml:"Tags"`
}

// NewCloudFrontStreamingDistribution constructor creates a new CloudFrontStreamingDistribution
func NewCloudFrontStreamingDistribution(properties CloudFrontStreamingDistributionProperties, deps ...interface{}) CloudFrontStreamingDistribution {
	return CloudFrontStreamingDistribution{
		Type:       "AWS::CloudFront::StreamingDistribution",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseCloudFrontStreamingDistribution parses CloudFrontStreamingDistribution
func ParseCloudFrontStreamingDistribution(
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
	var resource CloudFrontStreamingDistribution
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

// ParseCloudFrontStreamingDistribution validator
func (resource CloudFrontStreamingDistribution) Validate() []error {
	return resource.Properties.Validate()
}

// ParseCloudFrontStreamingDistributionProperties validator
func (resource CloudFrontStreamingDistributionProperties) Validate() []error {
	errors := []error{}
	if resource.StreamingDistributionConfig == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'StreamingDistributionConfig'"))
	} else {
		errors = append(errors, resource.StreamingDistributionConfig.Validate()...)
	}
	if resource.Tags == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Tags'"))
	}
	return errors
}