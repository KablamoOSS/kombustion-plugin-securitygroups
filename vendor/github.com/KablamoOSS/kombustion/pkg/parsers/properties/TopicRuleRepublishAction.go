package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// TopicRuleRepublishAction Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iot-topicrule-republishaction.html
type TopicRuleRepublishAction struct {
	RoleArn interface{} `yaml:"RoleArn"`
	Topic   interface{} `yaml:"Topic"`
}

// TopicRuleRepublishAction validation
func (resource TopicRuleRepublishAction) Validate() []error {
	errors := []error{}

	if resource.RoleArn == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'RoleArn'"))
	}
	if resource.Topic == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Topic'"))
	}
	return errors
}