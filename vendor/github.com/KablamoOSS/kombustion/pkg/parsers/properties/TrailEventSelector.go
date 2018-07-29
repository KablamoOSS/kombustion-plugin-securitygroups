package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// TrailEventSelector Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudtrail-trail-eventselector.html
type TrailEventSelector struct {
	IncludeManagementEvents interface{} `yaml:"IncludeManagementEvents,omitempty"`
	ReadWriteType           interface{} `yaml:"ReadWriteType,omitempty"`
	DataResources           interface{} `yaml:"DataResources,omitempty"`
}

// TrailEventSelector validation
func (resource TrailEventSelector) Validate() []error {
	errors := []error{}

	return errors
}