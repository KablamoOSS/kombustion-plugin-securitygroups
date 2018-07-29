package properties

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

// SpotFleetInstanceNetworkInterfaceSpecification Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-spotfleet-spotfleetrequestconfigdata-launchspecifications-networkinterfaces.html
type SpotFleetInstanceNetworkInterfaceSpecification struct {
	AssociatePublicIpAddress       interface{} `yaml:"AssociatePublicIpAddress,omitempty"`
	DeleteOnTermination            interface{} `yaml:"DeleteOnTermination,omitempty"`
	Description                    interface{} `yaml:"Description,omitempty"`
	DeviceIndex                    interface{} `yaml:"DeviceIndex,omitempty"`
	Ipv6AddressCount               interface{} `yaml:"Ipv6AddressCount,omitempty"`
	NetworkInterfaceId             interface{} `yaml:"NetworkInterfaceId,omitempty"`
	SecondaryPrivateIpAddressCount interface{} `yaml:"SecondaryPrivateIpAddressCount,omitempty"`
	SubnetId                       interface{} `yaml:"SubnetId,omitempty"`
	Groups                         interface{} `yaml:"Groups,omitempty"`
	Ipv6Addresses                  interface{} `yaml:"Ipv6Addresses,omitempty"`
	PrivateIpAddresses             interface{} `yaml:"PrivateIpAddresses,omitempty"`
}

// SpotFleetInstanceNetworkInterfaceSpecification validation
func (resource SpotFleetInstanceNetworkInterfaceSpecification) Validate() []error {
	errors := []error{}

	return errors
}