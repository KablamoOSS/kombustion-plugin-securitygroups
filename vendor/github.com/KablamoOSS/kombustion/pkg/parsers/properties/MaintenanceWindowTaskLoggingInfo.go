package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// MaintenanceWindowTaskLoggingInfo Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssm-maintenancewindowtask-logginginfo.html
type MaintenanceWindowTaskLoggingInfo struct {
	Region   interface{} `yaml:"Region"`
	S3Bucket interface{} `yaml:"S3Bucket"`
	S3Prefix interface{} `yaml:"S3Prefix,omitempty"`
}

// MaintenanceWindowTaskLoggingInfo validation
func (resource MaintenanceWindowTaskLoggingInfo) Validate() []error {
	errors := []error{}

	if resource.Region == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Region'"))
	}
	if resource.S3Bucket == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'S3Bucket'"))
	}
	return errors
}