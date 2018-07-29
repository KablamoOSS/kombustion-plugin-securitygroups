package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// DataPipelinePipeline Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-datapipeline-pipeline.html
type DataPipelinePipeline struct {
	Type       string                         `yaml:"Type"`
	Properties DataPipelinePipelineProperties `yaml:"Properties"`
	Condition  interface{}                    `yaml:"Condition,omitempty"`
	Metadata   interface{}                    `yaml:"Metadata,omitempty"`
	DependsOn  interface{}                    `yaml:"DependsOn,omitempty"`
}

// DataPipelinePipeline Properties
type DataPipelinePipelineProperties struct {
	Activate         interface{} `yaml:"Activate,omitempty"`
	Description      interface{} `yaml:"Description,omitempty"`
	Name             interface{} `yaml:"Name"`
	ParameterObjects interface{} `yaml:"ParameterObjects"`
	ParameterValues  interface{} `yaml:"ParameterValues,omitempty"`
	PipelineObjects  interface{} `yaml:"PipelineObjects,omitempty"`
	PipelineTags     interface{} `yaml:"PipelineTags,omitempty"`
}

// NewDataPipelinePipeline constructor creates a new DataPipelinePipeline
func NewDataPipelinePipeline(properties DataPipelinePipelineProperties, deps ...interface{}) DataPipelinePipeline {
	return DataPipelinePipeline{
		Type:       "AWS::DataPipeline::Pipeline",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseDataPipelinePipeline parses DataPipelinePipeline
func ParseDataPipelinePipeline(
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
	var resource DataPipelinePipeline
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

// ParseDataPipelinePipeline validator
func (resource DataPipelinePipeline) Validate() []error {
	return resource.Properties.Validate()
}

// ParseDataPipelinePipelineProperties validator
func (resource DataPipelinePipelineProperties) Validate() []error {
	errors := []error{}
	if resource.Name == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Name'"))
	}
	if resource.ParameterObjects == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'ParameterObjects'"))
	}
	return errors
}
