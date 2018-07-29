package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// PipelineParameterValue Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-datapipeline-pipeline-parametervalues.html
type PipelineParameterValue struct {
	Id          interface{} `yaml:"Id"`
	StringValue interface{} `yaml:"StringValue"`
}

// PipelineParameterValue validation
func (resource PipelineParameterValue) Validate() []error {
	errors := []error{}

	if resource.Id == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Id'"))
	}
	if resource.StringValue == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'StringValue'"))
	}
	return errors
}
