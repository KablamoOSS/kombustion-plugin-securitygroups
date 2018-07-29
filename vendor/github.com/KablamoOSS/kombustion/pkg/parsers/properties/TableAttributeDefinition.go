package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// TableAttributeDefinition Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dynamodb-attributedef.html
type TableAttributeDefinition struct {
	AttributeName interface{} `yaml:"AttributeName"`
	AttributeType interface{} `yaml:"AttributeType"`
}

// TableAttributeDefinition validation
func (resource TableAttributeDefinition) Validate() []error {
	errors := []error{}

	if resource.AttributeName == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'AttributeName'"))
	}
	if resource.AttributeType == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'AttributeType'"))
	}
	return errors
}