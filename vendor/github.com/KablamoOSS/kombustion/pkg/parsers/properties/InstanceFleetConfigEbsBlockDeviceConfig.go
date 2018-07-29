package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// InstanceFleetConfigEbsBlockDeviceConfig Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticmapreduce-instancefleetconfig-ebsblockdeviceconfig.html
type InstanceFleetConfigEbsBlockDeviceConfig struct {
	VolumesPerInstance  interface{}                             `yaml:"VolumesPerInstance,omitempty"`
	VolumeSpecification *InstanceFleetConfigVolumeSpecification `yaml:"VolumeSpecification"`
}

// InstanceFleetConfigEbsBlockDeviceConfig validation
func (resource InstanceFleetConfigEbsBlockDeviceConfig) Validate() []error {
	errors := []error{}

	if resource.VolumeSpecification == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'VolumeSpecification'"))
	} else {
		errors = append(errors, resource.VolumeSpecification.Validate()...)
	}
	return errors
}