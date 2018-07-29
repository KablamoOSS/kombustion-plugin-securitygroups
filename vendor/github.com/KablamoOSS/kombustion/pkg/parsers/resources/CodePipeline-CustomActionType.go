package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/pkg/parsers/properties"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// CodePipelineCustomActionType Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codepipeline-customactiontype.html
type CodePipelineCustomActionType struct {
	Type       string                                 `yaml:"Type"`
	Properties CodePipelineCustomActionTypeProperties `yaml:"Properties"`
	Condition  interface{}                            `yaml:"Condition,omitempty"`
	Metadata   interface{}                            `yaml:"Metadata,omitempty"`
	DependsOn  interface{}                            `yaml:"DependsOn,omitempty"`
}

// CodePipelineCustomActionType Properties
type CodePipelineCustomActionTypeProperties struct {
	Category                interface{}                                 `yaml:"Category"`
	Provider                interface{}                                 `yaml:"Provider"`
	Version                 interface{}                                 `yaml:"Version,omitempty"`
	Settings                *properties.CustomActionTypeSettings        `yaml:"Settings,omitempty"`
	ConfigurationProperties interface{}                                 `yaml:"ConfigurationProperties,omitempty"`
	InputArtifactDetails    *properties.CustomActionTypeArtifactDetails `yaml:"InputArtifactDetails"`
	OutputArtifactDetails   *properties.CustomActionTypeArtifactDetails `yaml:"OutputArtifactDetails"`
}

// NewCodePipelineCustomActionType constructor creates a new CodePipelineCustomActionType
func NewCodePipelineCustomActionType(properties CodePipelineCustomActionTypeProperties, deps ...interface{}) CodePipelineCustomActionType {
	return CodePipelineCustomActionType{
		Type:       "AWS::CodePipeline::CustomActionType",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseCodePipelineCustomActionType parses CodePipelineCustomActionType
func ParseCodePipelineCustomActionType(
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
	var resource CodePipelineCustomActionType
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

// ParseCodePipelineCustomActionType validator
func (resource CodePipelineCustomActionType) Validate() []error {
	return resource.Properties.Validate()
}

// ParseCodePipelineCustomActionTypeProperties validator
func (resource CodePipelineCustomActionTypeProperties) Validate() []error {
	errors := []error{}
	if resource.Category == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Category'"))
	}
	if resource.Provider == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Provider'"))
	}
	if resource.InputArtifactDetails == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'InputArtifactDetails'"))
	} else {
		errors = append(errors, resource.InputArtifactDetails.Validate()...)
	}
	if resource.OutputArtifactDetails == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'OutputArtifactDetails'"))
	} else {
		errors = append(errors, resource.OutputArtifactDetails.Validate()...)
	}
	return errors
}