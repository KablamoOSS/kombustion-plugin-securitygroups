package securitygroups

type NetworkSecurityGroupsConfig struct {
	Properties struct {
		Description string   `yaml:"Description"`
		Ingress     []string `yaml:"Ingress"`
		Egress      []string `yaml:"Egress"`
	} `yaml:"Properties"`
}
