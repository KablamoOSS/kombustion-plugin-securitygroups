package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// RecordSetGeoLocation Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-route53-recordset-geolocation.html
type RecordSetGeoLocation struct {
	ContinentCode   interface{} `yaml:"ContinentCode,omitempty"`
	CountryCode     interface{} `yaml:"CountryCode,omitempty"`
	SubdivisionCode interface{} `yaml:"SubdivisionCode,omitempty"`
}

// RecordSetGeoLocation validation
func (resource RecordSetGeoLocation) Validate() []error {
	errors := []error{}

	return errors
}