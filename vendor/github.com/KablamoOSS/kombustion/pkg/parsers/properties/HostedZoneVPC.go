package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// HostedZoneVPC Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone-hostedzonevpcs.html
type HostedZoneVPC struct {
	VPCId     interface{} `yaml:"VPCId"`
	VPCRegion interface{} `yaml:"VPCRegion"`
}

// HostedZoneVPC validation
func (resource HostedZoneVPC) Validate() []error {
	errors := []error{}

	if resource.VPCId == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'VPCId'"))
	}
	if resource.VPCRegion == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'VPCRegion'"))
	}
	return errors
}