package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// DeploymentMethodSetting Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-deployment-stagedescription-methodsetting.html
type DeploymentMethodSetting struct {
	CacheDataEncrypted   interface{} `yaml:"CacheDataEncrypted,omitempty"`
	CacheTtlInSeconds    interface{} `yaml:"CacheTtlInSeconds,omitempty"`
	CachingEnabled       interface{} `yaml:"CachingEnabled,omitempty"`
	DataTraceEnabled     interface{} `yaml:"DataTraceEnabled,omitempty"`
	HttpMethod           interface{} `yaml:"HttpMethod,omitempty"`
	LoggingLevel         interface{} `yaml:"LoggingLevel,omitempty"`
	MetricsEnabled       interface{} `yaml:"MetricsEnabled,omitempty"`
	ResourcePath         interface{} `yaml:"ResourcePath,omitempty"`
	ThrottlingBurstLimit interface{} `yaml:"ThrottlingBurstLimit,omitempty"`
	ThrottlingRateLimit  interface{} `yaml:"ThrottlingRateLimit,omitempty"`
}

// DeploymentMethodSetting validation
func (resource DeploymentMethodSetting) Validate() []error {
	errors := []error{}

	return errors
}