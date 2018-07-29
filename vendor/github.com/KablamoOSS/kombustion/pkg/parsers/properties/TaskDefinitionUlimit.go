package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// TaskDefinitionUlimit Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecs-taskdefinition-containerdefinitions-ulimit.html
type TaskDefinitionUlimit struct {
	HardLimit interface{} `yaml:"HardLimit"`
	Name      interface{} `yaml:"Name"`
	SoftLimit interface{} `yaml:"SoftLimit"`
}

// TaskDefinitionUlimit validation
func (resource TaskDefinitionUlimit) Validate() []error {
	errors := []error{}

	if resource.HardLimit == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'HardLimit'"))
	}
	if resource.Name == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'Name'"))
	}
	if resource.SoftLimit == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'SoftLimit'"))
	}
	return errors
}