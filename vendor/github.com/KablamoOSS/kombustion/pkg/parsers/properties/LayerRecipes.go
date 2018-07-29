package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// LayerRecipes Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opsworks-layer-recipes.html
type LayerRecipes struct {
	Configure interface{} `yaml:"Configure,omitempty"`
	Deploy    interface{} `yaml:"Deploy,omitempty"`
	Setup     interface{} `yaml:"Setup,omitempty"`
	Shutdown  interface{} `yaml:"Shutdown,omitempty"`
	Undeploy  interface{} `yaml:"Undeploy,omitempty"`
}

// LayerRecipes validation
func (resource LayerRecipes) Validate() []error {
	errors := []error{}

	return errors
}