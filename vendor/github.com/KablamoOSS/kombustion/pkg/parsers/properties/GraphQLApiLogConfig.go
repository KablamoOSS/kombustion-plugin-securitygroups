package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// GraphQLApiLogConfig Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-appsync-graphqlapi-logconfig.html
type GraphQLApiLogConfig struct {
	CloudWatchLogsRoleArn interface{} `yaml:"CloudWatchLogsRoleArn,omitempty"`
	FieldLogLevel         interface{} `yaml:"FieldLogLevel,omitempty"`
}

// GraphQLApiLogConfig validation
func (resource GraphQLApiLogConfig) Validate() []error {
	errors := []error{}

	return errors
}
