package resources

// Code generated by go generate; DO NOT EDIT.
// It's generated by "github.com/KablamoOSS/kombustion/generate"

import (
	"fmt"
	"github.com/KablamoOSS/kombustion/pkg/parsers/properties"
	"github.com/KablamoOSS/kombustion/types"
	yaml "github.com/KablamoOSS/yaml"
)

// RedshiftCluster Documentation: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html
type RedshiftCluster struct {
	Type       string                    `yaml:"Type"`
	Properties RedshiftClusterProperties `yaml:"Properties"`
	Condition  interface{}               `yaml:"Condition,omitempty"`
	Metadata   interface{}               `yaml:"Metadata,omitempty"`
	DependsOn  interface{}               `yaml:"DependsOn,omitempty"`
}

// RedshiftCluster Properties
type RedshiftClusterProperties struct {
	AllowVersionUpgrade              interface{}                          `yaml:"AllowVersionUpgrade,omitempty"`
	AutomatedSnapshotRetentionPeriod interface{}                          `yaml:"AutomatedSnapshotRetentionPeriod,omitempty"`
	AvailabilityZone                 interface{}                          `yaml:"AvailabilityZone,omitempty"`
	ClusterIdentifier                interface{}                          `yaml:"ClusterIdentifier,omitempty"`
	ClusterParameterGroupName        interface{}                          `yaml:"ClusterParameterGroupName,omitempty"`
	ClusterSubnetGroupName           interface{}                          `yaml:"ClusterSubnetGroupName,omitempty"`
	ClusterType                      interface{}                          `yaml:"ClusterType"`
	ClusterVersion                   interface{}                          `yaml:"ClusterVersion,omitempty"`
	DBName                           interface{}                          `yaml:"DBName"`
	ElasticIp                        interface{}                          `yaml:"ElasticIp,omitempty"`
	Encrypted                        interface{}                          `yaml:"Encrypted,omitempty"`
	HsmClientCertificateIdentifier   interface{}                          `yaml:"HsmClientCertificateIdentifier,omitempty"`
	HsmConfigurationIdentifier       interface{}                          `yaml:"HsmConfigurationIdentifier,omitempty"`
	KmsKeyId                         interface{}                          `yaml:"KmsKeyId,omitempty"`
	MasterUserPassword               interface{}                          `yaml:"MasterUserPassword"`
	MasterUsername                   interface{}                          `yaml:"MasterUsername"`
	NodeType                         interface{}                          `yaml:"NodeType"`
	NumberOfNodes                    interface{}                          `yaml:"NumberOfNodes,omitempty"`
	OwnerAccount                     interface{}                          `yaml:"OwnerAccount,omitempty"`
	Port                             interface{}                          `yaml:"Port,omitempty"`
	PreferredMaintenanceWindow       interface{}                          `yaml:"PreferredMaintenanceWindow,omitempty"`
	PubliclyAccessible               interface{}                          `yaml:"PubliclyAccessible,omitempty"`
	SnapshotClusterIdentifier        interface{}                          `yaml:"SnapshotClusterIdentifier,omitempty"`
	SnapshotIdentifier               interface{}                          `yaml:"SnapshotIdentifier,omitempty"`
	LoggingProperties                *properties.ClusterLoggingProperties `yaml:"LoggingProperties,omitempty"`
	ClusterSecurityGroups            interface{}                          `yaml:"ClusterSecurityGroups,omitempty"`
	IamRoles                         interface{}                          `yaml:"IamRoles,omitempty"`
	Tags                             interface{}                          `yaml:"Tags,omitempty"`
	VpcSecurityGroupIds              interface{}                          `yaml:"VpcSecurityGroupIds,omitempty"`
}

// NewRedshiftCluster constructor creates a new RedshiftCluster
func NewRedshiftCluster(properties RedshiftClusterProperties, deps ...interface{}) RedshiftCluster {
	return RedshiftCluster{
		Type:       "AWS::Redshift::Cluster",
		Properties: properties,
		DependsOn:  deps,
	}
}

// ParseRedshiftCluster parses RedshiftCluster
func ParseRedshiftCluster(
	name string,
	data string,
) (
	source string,
	conditions types.TemplateObject,
	metadata types.TemplateObject,
	mappings types.TemplateObject,
	outputs types.TemplateObject,
	parameters types.TemplateObject,
	resources types.TemplateObject,
	transform types.TemplateObject,
	errors []error,
) {
	source = "kombustion-core-resources"
	var resource RedshiftCluster
	err := yaml.Unmarshal([]byte(data), &resource)

	if err != nil {
		errors = append(errors, err)
		return
	}

	if validateErrs := resource.Properties.Validate(); len(errors) > 0 {
		errors = append(errors, validateErrs...)
		return
	}

	resources = types.TemplateObject{name: resource}

	return
}

// ParseRedshiftCluster validator
func (resource RedshiftCluster) Validate() []error {
	return resource.Properties.Validate()
}

// ParseRedshiftClusterProperties validator
func (resource RedshiftClusterProperties) Validate() []error {
	errors := []error{}
	if resource.ClusterType == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'ClusterType'"))
	}
	if resource.DBName == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'DBName'"))
	}
	if resource.MasterUserPassword == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'MasterUserPassword'"))
	}
	if resource.MasterUsername == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'MasterUsername'"))
	}
	if resource.NodeType == nil {
		errors = append(errors, fmt.Errorf("Missing required field 'NodeType'"))
	}
	return errors
}
