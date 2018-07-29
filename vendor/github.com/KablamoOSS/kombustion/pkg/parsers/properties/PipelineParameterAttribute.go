package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// PipelineParameterAttribute Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-datapipeline-pipeline-parameterobjects-attributes.html
type PipelineParameterAttribute struct {
	Key         interface{} `yaml:"Key"`
	StringValue interface{} `yaml:"StringValue"`
}

// PipelineParameterAttribute validation
func (resource PipelineParameterAttribute) Validate() []error {
	errors := []error{}

	if resource.Key == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Key'"))
	}
	if resource.StringValue == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'StringValue'"))
	}
	return errors
}