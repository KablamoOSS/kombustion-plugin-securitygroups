package securitygroups

import "fmt"

// Validate - input Config validation
func (config NetworkSecurityGroupsConfig) Validate() (errors []error) {
	// Enforce required props
	if config.Properties.Description == "" {
		errors = append(errors, fmt.Errorf("Missing SecGroup description'"))
	}
	return
}
