package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// DeploymentGroupDeploymentStyle Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codedeploy-deploymentgroup-deploymentstyle.html
type DeploymentGroupDeploymentStyle struct {
	DeploymentOption interface{} `yaml:"DeploymentOption,omitempty"`
	DeploymentType   interface{} `yaml:"DeploymentType,omitempty"`
}

// DeploymentGroupDeploymentStyle validation
func (resource DeploymentGroupDeploymentStyle) Validate() []error {
	errors := []error{}

	return errors
}