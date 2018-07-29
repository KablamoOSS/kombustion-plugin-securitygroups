package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import "fmt"

// ApplicationOutputOutput Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-kinesisanalytics-applicationoutput-output.html
type ApplicationOutputOutput struct {
	Name                  interface{}                             `yaml:"Name,omitempty"`
	LambdaOutput          *ApplicationOutputLambdaOutput          `yaml:"LambdaOutput,omitempty"`
	KinesisStreamsOutput  *ApplicationOutputKinesisStreamsOutput  `yaml:"KinesisStreamsOutput,omitempty"`
	KinesisFirehoseOutput *ApplicationOutputKinesisFirehoseOutput `yaml:"KinesisFirehoseOutput,omitempty"`
	DestinationSchema     *ApplicationOutputDestinationSchema     `yaml:"DestinationSchema"`
}

// ApplicationOutputOutput validation
func (resource ApplicationOutputOutput) Validate() []error {
	errors := []error{}

	if resource.DestinationSchema == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'DestinationSchema'"))
	} else {
		errors = append(errors, resource.DestinationSchema.Validate()...)
	}
	return errors
}