package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// DistributionS3OriginConfig Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-s3originconfig.html
type DistributionS3OriginConfig struct {
	OriginAccessIdentity interface{} `yaml:"OriginAccessIdentity,omitempty"`
}

// DistributionS3OriginConfig validation
func (resource DistributionS3OriginConfig) Validate() []error {
	errors := []error{}

	return errors
}