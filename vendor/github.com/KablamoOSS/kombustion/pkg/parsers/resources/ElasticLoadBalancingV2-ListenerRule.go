package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// ElasticLoadBalancingV2ListenerRule Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html
type ElasticLoadBalancingV2ListenerRule struct {
	Type       string                                       `yaml:"Type"`
	Properties ElasticLoadBalancingV2ListenerRuleProperties `yaml:"Properties"`
	Condition  interface{}                                  `yaml:"Condition,omitempty"`
	Metadata   interface{}                                  `yaml:"Metadata,omitempty"`
	DependsOn  interface{}                                  `yaml:"DependsOn,omitempty"`
}

// ElasticLoadBalancingV2ListenerRule Properties
type ElasticLoadBalancingV2ListenerRuleProperties struct {
	ListenerArn interface{} `yaml:"ListenerArn"`
	Priority    interface{} `yaml:"Priority"`
	Actions     interface{} `yaml:"Actions"`
	Conditions  interface{} `yaml:"Conditions"`
}

// NewElasticLoadBalancingV2ListenerRule constructor creates a new ElasticLoadBalancingV2ListenerRule
func NewElasticLoadBalancingV2ListenerRule(properties ElasticLoadBalancingV2ListenerRuleProperties, deps ...interface{}) ElasticLoadBalancingV2ListenerRule {
	return ElasticLoadBalancingV2ListenerRule{
		Type:       "AWS::ElasticLoadBalancingV2::ListenerRule",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseElasticLoadBalancingV2ListenerRule parses ElasticLoadBalancingV2ListenerRule
func ParseElasticLoadBalancingV2ListenerRule(
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
	var resource ElasticLoadBalancingV2ListenerRule
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

// ParseElasticLoadBalancingV2ListenerRule validator
func (resource ElasticLoadBalancingV2ListenerRule) Validate() []error {
	return resource.Properties.Validate()
}

// ParseElasticLoadBalancingV2ListenerRuleProperties validator
func (resource ElasticLoadBalancingV2ListenerRuleProperties) Validate() []error {
	errors := []error{}
	if resource.ListenerArn == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'ListenerArn'"))
	}
	if resource.Priority == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Priority'"))
	}
	if resource.Actions == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Actions'"))
	}
	if resource.Conditions == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Conditions'"))
	}
	return errors
}
