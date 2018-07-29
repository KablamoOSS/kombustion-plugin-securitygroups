package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// RepositoryLifecyclePolicy Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ecr-repository-lifecyclepolicy.html
type RepositoryLifecyclePolicy struct {
	LifecyclePolicyText interface{} `yaml:"LifecyclePolicyText,omitempty"`
	RegistryId          interface{} `yaml:"RegistryId,omitempty"`
}

// RepositoryLifecyclePolicy validation
func (resource RepositoryLifecyclePolicy) Validate() []error {
	errors := []error{}

	return errors
}