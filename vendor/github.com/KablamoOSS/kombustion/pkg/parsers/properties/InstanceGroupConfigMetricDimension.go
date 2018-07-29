package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// InstanceGroupConfigMetricDimension Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-metricdimension.html
type InstanceGroupConfigMetricDimension struct {
	Key   interface{} `yaml:"Key"`
	Value interface{} `yaml:"Value"`
}

// InstanceGroupConfigMetricDimension validation
func (resource InstanceGroupConfigMetricDimension) Validate() []error {
	errors := []error{}

	if resource.Key == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Key'"))
	}
	if resource.Value == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Value'"))
	}
	return errors
}