package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// UserLoginProfile Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user-loginprofile.html
type UserLoginProfile struct {
	Password              interface{} `yaml:"Password"`
	PasswordResetRequired interface{} `yaml:"PasswordResetRequired,omitempty"`
}

// UserLoginProfile validation
func (resource UserLoginProfile) Validate() []error {
	errors := []error{}

	if resource.Password == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Password'"))
	}
	return errors
}
