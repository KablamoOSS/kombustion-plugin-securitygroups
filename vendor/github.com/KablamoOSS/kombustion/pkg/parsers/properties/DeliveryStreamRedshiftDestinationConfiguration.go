package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// DeliveryStreamRedshiftDestinationConfiguration Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-kinesisfirehose-deliverystream-redshiftdestinationconfiguration.html
type DeliveryStreamRedshiftDestinationConfiguration struct {
	ClusterJDBCURL           interface{}                               `yaml:"ClusterJDBCURL"`
	Password                 interface{}                               `yaml:"Password"`
	RoleARN                  interface{}                               `yaml:"RoleARN"`
	Username                 interface{}                               `yaml:"Username"`
	S3Configuration          *DeliveryStreamS3DestinationConfiguration `yaml:"S3Configuration"`
	ProcessingConfiguration  *DeliveryStreamProcessingConfiguration    `yaml:"ProcessingConfiguration,omitempty"`
	CopyCommand              *DeliveryStreamCopyCommand                `yaml:"CopyCommand"`
	CloudWatchLoggingOptions *DeliveryStreamCloudWatchLoggingOptions   `yaml:"CloudWatchLoggingOptions,omitempty"`
}

// DeliveryStreamRedshiftDestinationConfiguration validation
func (resource DeliveryStreamRedshiftDestinationConfiguration) Validate() []error {
	errors := []error{}

	if resource.ClusterJDBCURL == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'ClusterJDBCURL'"))
	}
	if resource.Password == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Password'"))
	}
	if resource.RoleARN == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'RoleARN'"))
	}
	if resource.Username == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Username'"))
	}
	if resource.S3Configuration == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'S3Configuration'"))
	} else {
		errors = append(errors, resource.S3Configuration.Validate()...)
	}
	if resource.CopyCommand == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'CopyCommand'"))
	} else {
		errors = append(errors, resource.CopyCommand.Validate()...)
	}
	return errors
}
