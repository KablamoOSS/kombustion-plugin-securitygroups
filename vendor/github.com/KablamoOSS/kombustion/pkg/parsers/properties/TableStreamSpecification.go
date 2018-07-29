package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// TableStreamSpecification Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dynamodb-streamspecification.html
type TableStreamSpecification struct {
	StreamViewType interface{} `yaml:"StreamViewType"`
}

// TableStreamSpecification validation
func (resource TableStreamSpecification) Validate() []error {
	errors := []error{}

	if resource.StreamViewType == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'StreamViewType'"))
	}
	return errors
}