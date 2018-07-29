package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// DistributionLambdaFunctionAssociation Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-lambdafunctionassociation.html
type DistributionLambdaFunctionAssociation struct {
	EventType         interface{} `yaml:"EventType,omitempty"`
	LambdaFunctionARN interface{} `yaml:"LambdaFunctionARN,omitempty"`
}

// DistributionLambdaFunctionAssociation validation
func (resource DistributionLambdaFunctionAssociation) Validate() []error {
	errors := []error{}

	return errors
}
