package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// ProjectVpcConfig Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-vpcconfig.html
type ProjectVpcConfig struct {
	VpcId            interface{} `yaml:"VpcId"`
	SecurityGroupIds interface{} `yaml:"SecurityGroupIds"`
	Subnets          interface{} `yaml:"Subnets"`
}

// ProjectVpcConfig validation
func (resource ProjectVpcConfig) Validate() []error {
	errors := []error{}

	if resource.VpcId == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'VpcId'"))
	}
	if resource.SecurityGroupIds == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'SecurityGroupIds'"))
	}
	if resource.Subnets == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Subnets'"))
	}
	return errors
}