package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// TopicRuleKinesisAction Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iot-topicrule-kinesisaction.html
type TopicRuleKinesisAction struct {
	PartitionKey interface{} `yaml:"PartitionKey,omitempty"`
	RoleArn      interface{} `yaml:"RoleArn"`
	StreamName   interface{} `yaml:"StreamName"`
}

// TopicRuleKinesisAction validation
func (resource TopicRuleKinesisAction) Validate() []error {
	errors := []error{}

	if resource.RoleArn == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'RoleArn'"))
	}
	if resource.StreamName == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'StreamName'"))
	}
	return errors
}