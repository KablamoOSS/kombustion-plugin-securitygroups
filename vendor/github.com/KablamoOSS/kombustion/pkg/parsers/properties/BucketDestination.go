package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// BucketDestination Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-destination.html
type BucketDestination struct {
	BucketAccountId interface{} `yaml:"BucketAccountId,omitempty"`
	BucketArn       interface{} `yaml:"BucketArn"`
	Format          interface{} `yaml:"Format"`
	Prefix          interface{} `yaml:"Prefix,omitempty"`
}

// BucketDestination validation
func (resource BucketDestination) Validate() []error {
	errors := []error{}

	if resource.BucketArn == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'BucketArn'"))
	}
	if resource.Format == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Format'"))
	}
	return errors
}