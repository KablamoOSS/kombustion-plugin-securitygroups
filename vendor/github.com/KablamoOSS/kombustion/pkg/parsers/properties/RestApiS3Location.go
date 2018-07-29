package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// RestApiS3Location Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-restapi-s3location.html
type RestApiS3Location struct {
	Bucket  interface{} `yaml:"Bucket,omitempty"`
	ETag    interface{} `yaml:"ETag,omitempty"`
	Key     interface{} `yaml:"Key,omitempty"`
	Version interface{} `yaml:"Version,omitempty"`
}

// RestApiS3Location validation
func (resource RestApiS3Location) Validate() []error {
	errors := []error{}

	return errors
}