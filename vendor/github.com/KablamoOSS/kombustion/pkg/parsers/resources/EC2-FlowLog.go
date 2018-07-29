package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// EC2FlowLog Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-flowlog.html
type EC2FlowLog struct {
	Type       string               `yaml:"Type"`
	Properties EC2FlowLogProperties `yaml:"Properties"`
	Condition  interface{}          `yaml:"Condition,omitempty"`
	Metadata   interface{}          `yaml:"Metadata,omitempty"`
	DependsOn  interface{}          `yaml:"DependsOn,omitempty"`
}

// EC2FlowLog Properties
type EC2FlowLogProperties struct {
	DeliverLogsPermissionArn interface{} `yaml:"DeliverLogsPermissionArn"`
	LogGroupName             interface{} `yaml:"LogGroupName"`
	ResourceId               interface{} `yaml:"ResourceId"`
	ResourceType             interface{} `yaml:"ResourceType"`
	TrafficType              interface{} `yaml:"TrafficType"`
}

// NewEC2FlowLog constructor creates a new EC2FlowLog
func NewEC2FlowLog(properties EC2FlowLogProperties, deps ...interface{}) EC2FlowLog {
	return EC2FlowLog{
		Type:       "AWS::EC2::FlowLog",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseEC2FlowLog parses EC2FlowLog
func ParseEC2FlowLog(
	name string,
	data string,
) (
	source string,
	conditions types.TemplateObject,
	metadata types.TemplateObject,
	mappings types.TemplateObject,
	outputs types.TemplateObject,
	parameters types.TemplateObject,
	resources types.TemplateObject,
	transform types.TemplateObject,
	errors []error,
) {
	source = "kombustion-core-resources"
	var resource EC2FlowLog
	err := yaml.Unmarshal([]byte(data), &resource)

	if err != nil {
		errors = append(errors, err)
		return
	}

	if validateErrs := resource.Properties.Validate(); len(errors) > 0 {
		errors = append(errors, validateErrs...)
		return
	}

	resources = types.TemplateObject{name: resource}

	return
}

// ParseEC2FlowLog validator
func (resource EC2FlowLog) Validate() []error {
	return resource.Properties.Validate()
}

// ParseEC2FlowLogProperties validator
func (resource EC2FlowLogProperties) Validate() []error {
	errors := []error{}
	if resource.DeliverLogsPermissionArn == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'DeliverLogsPermissionArn'"))
	}
	if resource.LogGroupName == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'LogGroupName'"))
	}
	if resource.ResourceId == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'ResourceId'"))
	}
	if resource.ResourceType == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'ResourceType'"))
	}
	if resource.TrafficType == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'TrafficType'"))
	}
	return errors
}
