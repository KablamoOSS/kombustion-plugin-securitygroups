package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// KinesisAnalyticsApplication Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesisanalytics-application.html
type KinesisAnalyticsApplication struct {
	Type       string                                `yaml:"Type"`
	Properties KinesisAnalyticsApplicationProperties `yaml:"Properties"`
	Condition  interface{}                           `yaml:"Condition,omitempty"`
	Metadata   interface{}                           `yaml:"Metadata,omitempty"`
	DependsOn  interface{}                           `yaml:"DependsOn,omitempty"`
}

// KinesisAnalyticsApplication Properties
type KinesisAnalyticsApplicationProperties struct {
	ApplicationCode        interface{} `yaml:"ApplicationCode,omitempty"`
	ApplicationDescription interface{} `yaml:"ApplicationDescription,omitempty"`
	ApplicationName        interface{} `yaml:"ApplicationName,omitempty"`
	Inputs                 interface{} `yaml:"Inputs"`
}

// NewKinesisAnalyticsApplication constructor creates a new KinesisAnalyticsApplication
func NewKinesisAnalyticsApplication(properties KinesisAnalyticsApplicationProperties, deps ...interface{}) KinesisAnalyticsApplication {
	return KinesisAnalyticsApplication{
		Type:       "AWS::KinesisAnalytics::Application",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseKinesisAnalyticsApplication parses KinesisAnalyticsApplication
func ParseKinesisAnalyticsApplication(
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
	var resource KinesisAnalyticsApplication
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

// ParseKinesisAnalyticsApplication validator
func (resource KinesisAnalyticsApplication) Validate() []error {
	return resource.Properties.Validate()
}

// ParseKinesisAnalyticsApplicationProperties validator
func (resource KinesisAnalyticsApplicationProperties) Validate() []error {
	errors := []error{}
	if resource.Inputs == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Inputs'"))
	}
	return errors
}
