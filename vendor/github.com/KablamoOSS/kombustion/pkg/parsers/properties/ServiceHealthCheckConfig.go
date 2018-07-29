package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// ServiceHealthCheckConfig Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-servicediscovery-service-healthcheckconfig.html
type ServiceHealthCheckConfig struct {
	FailureThreshold interface{} `yaml:"FailureThreshold,omitempty"`
	ResourcePath     interface{} `yaml:"ResourcePath,omitempty"`
	Type             interface{} `yaml:"Type"`
}

// ServiceHealthCheckConfig validation
func (resource ServiceHealthCheckConfig) Validate() []error {
	errors := []error{}

	if resource.Type == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Type'"))
	}
	return errors
}