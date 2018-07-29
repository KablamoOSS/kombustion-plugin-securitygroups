package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// BucketInventoryConfiguration Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-inventoryconfiguration.html
type BucketInventoryConfiguration struct {
	Enabled                interface{}        `yaml:"Enabled"`
	Id                     interface{}        `yaml:"Id"`
	IncludedObjectVersions interface{}        `yaml:"IncludedObjectVersions"`
	Prefix                 interface{}        `yaml:"Prefix,omitempty"`
	ScheduleFrequency      interface{}        `yaml:"ScheduleFrequency"`
	OptionalFields         interface{}        `yaml:"OptionalFields,omitempty"`
	Destination            *BucketDestination `yaml:"Destination"`
}

// BucketInventoryConfiguration validation
func (resource BucketInventoryConfiguration) Validate() []error {
	errors := []error{}

	if resource.Enabled == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Enabled'"))
	}
	if resource.Id == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Id'"))
	}
	if resource.IncludedObjectVersions == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'IncludedObjectVersions'"))
	}
	if resource.ScheduleFrequency == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'ScheduleFrequency'"))
	}
	if resource.Destination == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Destination'"))
	} else {
		errors = append(errors, resource.Destination.Validate()...)
	}
	return errors
}
