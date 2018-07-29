package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/pkg/parsers/properties"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// KinesisAnalyticsApplicationReferenceDataSource Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesisanalytics-applicationreferencedatasource.html
type KinesisAnalyticsApplicationReferenceDataSource struct {
	Type       string                                                   `yaml:"Type"`
	Properties KinesisAnalyticsApplicationReferenceDataSourceProperties `yaml:"Properties"`
	Condition  interface{}                                              `yaml:"Condition,omitempty"`
	Metadata   interface{}                                              `yaml:"Metadata,omitempty"`
	DependsOn  interface{}                                              `yaml:"DependsOn,omitempty"`
}

// KinesisAnalyticsApplicationReferenceDataSource Properties
type KinesisAnalyticsApplicationReferenceDataSourceProperties struct {
	ApplicationName     interface{}                                                   `yaml:"ApplicationName"`
	ReferenceDataSource *properties.ApplicationReferenceDataSourceReferenceDataSource `yaml:"ReferenceDataSource"`
}

// NewKinesisAnalyticsApplicationReferenceDataSource constructor creates a new KinesisAnalyticsApplicationReferenceDataSource
func NewKinesisAnalyticsApplicationReferenceDataSource(properties KinesisAnalyticsApplicationReferenceDataSourceProperties, deps ...interface{}) KinesisAnalyticsApplicationReferenceDataSource {
	return KinesisAnalyticsApplicationReferenceDataSource{
		Type:       "AWS::KinesisAnalytics::ApplicationReferenceDataSource",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseKinesisAnalyticsApplicationReferenceDataSource parses KinesisAnalyticsApplicationReferenceDataSource
func ParseKinesisAnalyticsApplicationReferenceDataSource(
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
	var resource KinesisAnalyticsApplicationReferenceDataSource
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

// ParseKinesisAnalyticsApplicationReferenceDataSource validator
func (resource KinesisAnalyticsApplicationReferenceDataSource) Validate() []error {
	return resource.Properties.Validate()
}

// ParseKinesisAnalyticsApplicationReferenceDataSourceProperties validator
func (resource KinesisAnalyticsApplicationReferenceDataSourceProperties) Validate() []error {
	errors := []error{}
	if resource.ApplicationName == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'ApplicationName'"))
	}
	if resource.ReferenceDataSource == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'ReferenceDataSource'"))
	} else {
		errors = append(errors, resource.ReferenceDataSource.Validate()...)
	}
	return errors
}
