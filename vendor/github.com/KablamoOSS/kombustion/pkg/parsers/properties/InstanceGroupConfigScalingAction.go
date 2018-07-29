package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// InstanceGroupConfigScalingAction Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancegroupconfig-scalingaction.html
type InstanceGroupConfigScalingAction struct {
	Market                           interface{}                                          `yaml:"Market,omitempty"`
	SimpleScalingPolicyConfiguration *InstanceGroupConfigSimpleScalingPolicyConfiguration `yaml:"SimpleScalingPolicyConfiguration"`
}

// InstanceGroupConfigScalingAction validation
func (resource InstanceGroupConfigScalingAction) Validate() []error {
	errors := []error{}

	if resource.SimpleScalingPolicyConfiguration == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'SimpleScalingPolicyConfiguration'"))
	} else {
		errors = append(errors, resource.SimpleScalingPolicyConfiguration.Validate()...)
	}
	return errors
}
