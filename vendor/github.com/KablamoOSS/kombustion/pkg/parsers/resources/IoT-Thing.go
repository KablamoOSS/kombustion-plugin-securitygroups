package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"github.com/KablamoOSS/kombustion/pkg/parsers/properties"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// IoTThing Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iot-thing.html
type IoTThing struct {
	Type       string             `yaml:"Type"`
	Properties IoTThingProperties `yaml:"Properties"`
	Condition  interface{}        `yaml:"Condition,omitempty"`
	Metadata   interface{}        `yaml:"Metadata,omitempty"`
	DependsOn  interface{}        `yaml:"DependsOn,omitempty"`
}

// IoTThing Properties
type IoTThingProperties struct {
	ThingName        interface{}                       `yaml:"ThingName,omitempty"`
	AttributePayload *properties.ThingAttributePayload `yaml:"AttributePayload,omitempty"`
}

// NewIoTThing constructor creates a new IoTThing
func NewIoTThing(properties IoTThingProperties, deps ...interface{}) IoTThing {
	return IoTThing{
		Type:       "AWS::IoT::Thing",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseIoTThing parses IoTThing
func ParseIoTThing(
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
	var resource IoTThing
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

// ParseIoTThing validator
func (resource IoTThing) Validate() []error {
	return resource.Properties.Validate()
}

// ParseIoTThingProperties validator
func (resource IoTThingProperties) Validate() []error {
	errors := []error{}
	return errors
}
