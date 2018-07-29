package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// LoadBalancerConnectionDrainingPolicy Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-elb-connectiondrainingpolicy.html
type LoadBalancerConnectionDrainingPolicy struct {
	Enabled interface{} `yaml:"Enabled"`
	Timeout interface{} `yaml:"Timeout,omitempty"`
}

// LoadBalancerConnectionDrainingPolicy validation
func (resource LoadBalancerConnectionDrainingPolicy) Validate() []error {
	errors := []error{}

	if resource.Enabled == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Enabled'"))
	}
	return errors
}