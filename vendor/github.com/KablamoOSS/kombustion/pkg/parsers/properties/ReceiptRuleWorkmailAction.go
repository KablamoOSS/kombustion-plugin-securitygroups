package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// ReceiptRuleWorkmailAction Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ses-receiptrule-workmailaction.html
type ReceiptRuleWorkmailAction struct {
	OrganizationArn interface{} `yaml:"OrganizationArn"`
	TopicArn        interface{} `yaml:"TopicArn,omitempty"`
}

// ReceiptRuleWorkmailAction validation
func (resource ReceiptRuleWorkmailAction) Validate() []error {
	errors := []error{}

	if resource.OrganizationArn == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'OrganizationArn'"))
	}
	return errors
}