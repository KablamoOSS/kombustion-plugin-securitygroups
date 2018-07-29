package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// ConfigurationSetEventDestinationDimensionConfiguration Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ses-configurationseteventdestination-dimensionconfiguration.html
type ConfigurationSetEventDestinationDimensionConfiguration struct {
	DefaultDimensionValue interface{} `yaml:"DefaultDimensionValue"`
	DimensionName         interface{} `yaml:"DimensionName"`
	DimensionValueSource  interface{} `yaml:"DimensionValueSource"`
}

// ConfigurationSetEventDestinationDimensionConfiguration validation
func (resource ConfigurationSetEventDestinationDimensionConfiguration) Validate() []error {
	errors := []error{}

	if resource.DefaultDimensionValue == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'DefaultDimensionValue'"))
	}
	if resource.DimensionName == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'DimensionName'"))
	}
	if resource.DimensionValueSource == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'DimensionValueSource'"))
	}
	return errors
}
