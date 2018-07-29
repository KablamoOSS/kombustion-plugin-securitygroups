package securitygroups

import (
	"strings"

	"github.com/KablamoOSS/kombustion/pkg/parsers/resources"
	cfResources "github.com/KablamoOSS/kombustion/pkg/parsers/resources"
	kombustionTypes "github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

//NetworkVPCConfig Main Object and construct

func splitSecGroupObject(data string, sectype string) (secobj interface{}) {
	secentry := strings.Split(data, ",")
	switch entrysize := len(secentry); entrysize {
	case 3:
		secentry = append(secentry, "0.0.0.0/0")
		secentry = append(secentry, "")
	case 4:
		secentry = append(secentry, "")
	}
	if sectype == "ingress" {
		secobj = resources.EC2SecurityGroupIngressProperties{
			CidrIp:      map[string]interface{}{"Ref": secentry[3]},
			FromPort:    secentry[1],
			ToPort:      secentry[2],
			IpProtocol:  secentry[0],
			Description: secentry[4],
		}
	} else {
		secobj = resources.EC2SecurityGroupEgressProperties{
			CidrIp:      map[string]interface{}{"Ref": secentry[3]},
			FromPort:    secentry[1],
			ToPort:      secentry[2],
			IpProtocol:  secentry[0],
			Description: secentry[4],
		}
	}
	return secobj
}

//ParseNetworkVPC parser builder.
func ParseNetworkSecurityGroups(name string,
	data string,
) (
	conditions kombustionTypes.TemplateObject,
	metadata kombustionTypes.TemplateObject,
	mappings kombustionTypes.TemplateObject,
	outputs kombustionTypes.TemplateObject,
	parameters kombustionTypes.TemplateObject,
	resources kombustionTypes.TemplateObject,
	transform kombustionTypes.TemplateObject,
	errors []error,
) {
	// Parse the config data
	var config NetworkSecurityGroupsConfig
	err := yaml.Unmarshal([]byte(data), &config)
	if err != nil {
		errors = append(errors, err)
		return
	}

	// validate the config
	config.Validate()

	// validate the config
	validateErrs := config.Validate()

	if validateErrs != nil {
		errors = append(errors, validateErrs...)
		return
	}

	// create a group of objects (each to be validated)
	resources = make(kombustionTypes.TemplateObject)

	var ingress = []cfResources.EC2SecurityGroupIngressProperties{}
	for _, obj := range config.Properties.Ingress {
		ingress = append(
			ingress, splitSecGroupObject(obj, "ingress").(cfResources.EC2SecurityGroupIngressProperties),
		)
	}

	var egress = []cfResources.EC2SecurityGroupEgressProperties{}
	for _, obj := range config.Properties.Egress {
		egress = append(
			egress, splitSecGroupObject(obj, "egress").(cfResources.EC2SecurityGroupEgressProperties),
		)
	}

	resources[name] = cfResources.NewEC2SecurityGroup(
		cfResources.EC2SecurityGroupProperties{
			GroupDescription:     config.Properties.Description,
			SecurityGroupIngress: ingress,
			SecurityGroupEgress:  egress,
		},
	)

	return
}
