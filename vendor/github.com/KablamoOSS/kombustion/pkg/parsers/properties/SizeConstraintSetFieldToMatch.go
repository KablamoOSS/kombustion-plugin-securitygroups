package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// SizeConstraintSetFieldToMatch Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-waf-sizeconstraintset-sizeconstraint-fieldtomatch.html
type SizeConstraintSetFieldToMatch struct {
	Data interface{} `yaml:"Data,omitempty"`
	Type interface{} `yaml:"Type"`
}

// SizeConstraintSetFieldToMatch validation
func (resource SizeConstraintSetFieldToMatch) Validate() []error {
	errors := []error{}

	if resource.Type == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Type'"))
	}
	return errors
}