package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// EndpointS3Settings Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-dms-endpoint-s3settings.html
type EndpointS3Settings struct {
	BucketFolder            interface{} `yaml:"BucketFolder,omitempty"`
	BucketName              interface{} `yaml:"BucketName,omitempty"`
	CompressionType         interface{} `yaml:"CompressionType,omitempty"`
	CsvDelimiter            interface{} `yaml:"CsvDelimiter,omitempty"`
	CsvRowDelimiter         interface{} `yaml:"CsvRowDelimiter,omitempty"`
	ExternalTableDefinition interface{} `yaml:"ExternalTableDefinition,omitempty"`
	ServiceAccessRoleArn    interface{} `yaml:"ServiceAccessRoleArn,omitempty"`
}

// EndpointS3Settings validation
func (resource EndpointS3Settings) Validate() []error {
	errors := []error{}

	return errors
}