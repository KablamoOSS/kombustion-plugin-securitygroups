package main

import (
	"github.com/KablamoOSS/kombustion-plugin-securitygroups/parsers/securitygroups"
	"github.com/KablamoOSS/kombustion/pkg/plugins/api"
	"github.com/KablamoOSS/kombustion/pkg/plugins/api/types"
)

var (
	version string
	name    string
)

func init() {
	if version == "" {
		version = "BUILT_FROM_SOURCE"
	}
	if name == "" {
		name = "kombustion-plugin-securitygroups"
	}
}

// Parsers functions
var Parsers = map[string]func(
	name string,
	data string,
) []byte{
	"SecurityGroups": api.RegisterParser(securitygroups.ParseNetworkSecurityGroups),
}

// Register plugin
func Register() []byte {
	return api.RegisterPlugin(types.Config{
		Name:    name,
		Version: version,
		Prefix:  "Kablamo::Network",
		Help: types.Help{
			Description: "A SecurityGroups Plugin",
			Types: []types.TypeMapping{
				{
					Name:        "Kablamo::Network::SecurityGroups",
					Description: "Creates a VPC and various components.",
					Config:      securitygroups.NetworkSecurityGroupsConfig{},
				},
			},
		},
	})
}

func main() {}
