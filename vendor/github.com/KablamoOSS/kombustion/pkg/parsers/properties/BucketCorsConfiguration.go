package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// BucketCorsConfiguration Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors.html
type BucketCorsConfiguration struct {
	CorsRules interface{} `yaml:"CorsRules"`
}

// BucketCorsConfiguration validation
func (resource BucketCorsConfiguration) Validate() []error {
	errors := []error{}

	if resource.CorsRules == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'CorsRules'"))
	}
	return errors
}