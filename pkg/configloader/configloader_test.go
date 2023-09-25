package configloader

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNewFactory(t *testing.T) {
	f, err := NewFactory(nil, nil, "PORTO_")
	assert.NoError(t, err)
	assert.NotNil(t, f)

	var c struct{}

	_, err = f.Load("notfound-config.yaml", &c)
	require.Error(t, err)
	assert.Equal(t, `file "notfound-config.yaml" not found in []`, err.Error())
}

func TestLoadYAML(t *testing.T) {
	cfgFile, err := GetAbsFilename("testdata/test_config.yaml", ".")
	require.NoError(t, err, "unable to determine config file")

	f, err := NewFactory(nil, []string{"testdata/override"}, "PORTO_")
	require.NoError(t, err)

	var c configuration
	_, err = f.Load(cfgFile, &c)
	require.NoError(t, err, "failed to load config: %v", cfgFile)
}

func TestLoadYAMLOverrideByHostname(t *testing.T) {
	cfgFile, err := GetAbsFilename("testdata/test_config.yaml", ".")
	require.NoError(t, err, "unable to determine config file")

	f, err := NewFactory(nil, []string{"testdata/override"}, "TEST_")
	require.NoError(t, err)

	os.Setenv("TEST_HOSTNAME", "UNIT_TEST")

	var c configuration
	_, err = f.Load(cfgFile, &c)
	require.NoError(t, err, "failed to load config: %v", cfgFile)
	assert.Equal(t, "UNIT_TEST", c.Environment) // lower cased
	assert.Equal(t, "local", c.Region)
	assert.Equal(t, "porto-pod", c.ServiceName)
	assert.NotEmpty(t, c.ClusterName)

	assert.Equal(t, fmt.Sprintf("/tmp/porto-%s/logs", c.Environment), c.Logs.Directory)
	assert.Equal(t, 3, c.Logs.MaxAgeDays)
	assert.Equal(t, 10, c.Logs.MaxSizeMb)

	assert.Equal(t, fmt.Sprintf("/tmp/porto-%s/audit", c.Environment), c.Audit.Directory)
	assert.Equal(t, 99, c.Audit.MaxAgeDays)
	assert.Equal(t, 99, c.Audit.MaxSizeMb)

	assert.Equal(t, "UNIT_TEST", c.Templates["environment"])
	assert.Equal(t, "UNIT_TEST", c.Templates["ENVIRONMENT"])

	b, err := yaml.Marshal(c)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "${")

	for k, v := range c.Templates {
		assert.NotContains(t, v, "${", "%s is not extrapolated: %s", k, v)
	}

	for idx, v := range c.List {
		assert.NotContains(t, v, "${", "list[%d] is not extrapolated: %s", idx, v)
	}
	assert.Len(t, c.List, 4)
}

func TestLoadYAMLWithOverride(t *testing.T) {
	cfgFile, err := GetAbsFilename("testdata/test_config.yaml", ".")
	require.NoError(t, err, "unable to determine config file")

	f, err := NewFactory(nil, []string{"testdata/override"}, "TEST_")
	require.NoError(t, err)

	os.Setenv("TEST_HOSTNAME", "UNIT_TEST")

	f.WithOverride("custom_list.yaml")
	f.WithEnvironment("test2")

	var c configuration
	_, err = f.Load(cfgFile, &c)
	require.NoError(t, err, "failed to load config: %v", cfgFile)
	assert.Equal(t, "test2", c.Environment)
	assert.Equal(t, "test-override", c.Region)
	assert.Equal(t, "porto-pod", c.ServiceName)
	assert.NotEmpty(t, c.ClusterName)

	assert.Equal(t, fmt.Sprintf("/tmp/porto-%s/logs", c.Environment), c.Logs.Directory)
	assert.Equal(t, 3, c.Logs.MaxAgeDays)
	assert.Equal(t, 10, c.Logs.MaxSizeMb)

	assert.Equal(t, fmt.Sprintf("/tmp/porto-%s/audit", c.Environment), c.Audit.Directory)
	assert.Equal(t, 99, c.Audit.MaxAgeDays)
	assert.Equal(t, 99, c.Audit.MaxSizeMb)

	assert.Equal(t, "test2", c.Templates["environment"])
	assert.Equal(t, "TEST2", c.Templates["ENVIRONMENT"])

	b, err := yaml.Marshal(c)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "${")

	for k, v := range c.Templates {
		assert.NotContains(t, v, "${", "%s is not extrapolated: %s", k, v)
	}

	for idx, v := range c.List {
		assert.NotContains(t, v, "${", "list[%d] is not extrapolated: %s", idx, v)
	}
	assert.Len(t, c.List, 5)
}

// configuration contains the user configurable data for the service
type configuration struct {

	// Region specifies the Region / Datacenter where the instance is running
	Region string `json:"region,omitempty" yaml:"region,omitempty"`

	// Environment specifies the environment where the instance is running: prod|stage|dev
	Environment string `json:"environment,omitempty" yaml:"environment,omitempty"`

	// ServiceName specifies the service name to be used in logs, metrics, etc
	ServiceName string `json:"service,omitempty" yaml:"service,omitempty"`

	// ClusterName specifies the cluster name
	ClusterName string `json:"cluster,omitempty" yaml:"cluster,omitempty"`

	// Audit contains configuration for the audit logger
	Audit Logger `json:"audit" yaml:"audit"`

	// Logs contains configuration for the logger
	Logs Logger `json:"logs" yaml:"logs"`

	Templates map[string]string `json:"templates" yaml:"templates"`

	List []string `json:"list" yaml:"list"`

	Map map[string]*Logger `json:"map_log" yaml:"map_log"`
}

// Logger contains information about the configuration of a logger/log rotation
type Logger struct {

	// Directory contains where to store the log files; if value is empty, them stderr is used for output
	Directory string `json:"directory,omitempty" yaml:"directory,omitempty"`

	// MaxAgeDays controls how old files are before deletion
	MaxAgeDays int `json:"max_age_days,omitempty" yaml:"max_age_days,omitempty"`

	// MaxSizeMb contols how large a single log file can be before its rotated
	MaxSizeMb int `json:"max_size_mb,omitempty" yaml:"max_size_mb,omitempty"`
}
