package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// AssociationS3OutputLocation Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ssm-association-s3outputlocation.html
type AssociationS3OutputLocation struct {
	OutputS3BucketName interface{} `yaml:"OutputS3BucketName,omitempty"`
	OutputS3KeyPrefix  interface{} `yaml:"OutputS3KeyPrefix,omitempty"`
}

// AssociationS3OutputLocation validation
func (resource AssociationS3OutputLocation) Validate() []error {
	errors := []error{}

	return errors
}