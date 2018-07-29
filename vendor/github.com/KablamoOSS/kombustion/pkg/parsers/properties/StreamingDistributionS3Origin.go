package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// StreamingDistributionS3Origin Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-streamingdistribution-s3origin.html
type StreamingDistributionS3Origin struct {
	DomainName           interface{} `yaml:"DomainName"`
	OriginAccessIdentity interface{} `yaml:"OriginAccessIdentity"`
}

// StreamingDistributionS3Origin validation
func (resource StreamingDistributionS3Origin) Validate() []error {
	errors := []error{}

	if resource.DomainName == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'DomainName'"))
	}
	if resource.OriginAccessIdentity == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'OriginAccessIdentity'"))
	}
	return errors
}