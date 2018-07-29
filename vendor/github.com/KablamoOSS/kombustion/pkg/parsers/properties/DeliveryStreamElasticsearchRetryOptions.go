package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// DeliveryStreamElasticsearchRetryOptions Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-kinesisfirehose-deliverystream-elasticsearchretryoptions.html
type DeliveryStreamElasticsearchRetryOptions struct {
	DurationInSeconds interface{} `yaml:"DurationInSeconds"`
}

// DeliveryStreamElasticsearchRetryOptions validation
func (resource DeliveryStreamElasticsearchRetryOptions) Validate() []error {
	errors := []error{}

	if resource.DurationInSeconds == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'DurationInSeconds'"))
	}
	return errors
}