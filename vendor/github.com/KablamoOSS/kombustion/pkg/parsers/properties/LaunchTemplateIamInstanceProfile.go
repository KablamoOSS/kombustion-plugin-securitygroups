package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// LaunchTemplateIamInstanceProfile Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-launchtemplate-launchtemplatedata-iaminstanceprofile.html
type LaunchTemplateIamInstanceProfile struct {
	Arn  interface{} `yaml:"Arn,omitempty"`
	Name interface{} `yaml:"Name,omitempty"`
}

// LaunchTemplateIamInstanceProfile validation
func (resource LaunchTemplateIamInstanceProfile) Validate() []error {
	errors := []error{}

	return errors
}