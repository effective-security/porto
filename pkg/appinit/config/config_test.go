package config_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/effective-security/porto/pkg/appinit/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCloudWatchAwsEndpointKey(t *testing.T) {
	t.Parallel()

	const endpoint = "http://localhost:4566"
	tcs := []struct {
		name     string
		yaml     string
		json     string
		expected string
	}{
		{
			name:     "aws_endpoint",
			yaml:     "aws_endpoint: " + endpoint,
			json:     `{"aws_endpoint":"` + endpoint + `"}`,
			expected: endpoint,
		},
		{
			// The untagged field used the encoders' default keys before v1.0.
			name: "legacy keys",
			yaml: "awsendpoint: " + endpoint,
			json: `{"AwsEndpoint":"` + endpoint + `"}`,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var fromYAML config.CloudWatch
			require.NoError(t, yaml.Unmarshal([]byte(tc.yaml), &fromYAML))
			assert.Equal(t, tc.expected, fromYAML.AwsEndpoint)

			var fromJSON config.CloudWatch
			require.NoError(t, json.Unmarshal([]byte(tc.json), &fromJSON))
			assert.Equal(t, tc.expected, fromJSON.AwsEndpoint)
		})
	}
}

func TestCloudWatchMarshal(t *testing.T) {
	t.Parallel()

	js, err := json.Marshal(config.CloudWatch{AwsRegion: "us-west-2"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"aws_region":"us-west-2","namespace":"","publish_interval":0,"with_sample_count":false}`, string(js))

	js, err = json.Marshal(config.CloudWatch{AwsEndpoint: "http://localhost:4566"})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(js, &m))
	assert.Equal(t, "http://localhost:4566", m["aws_endpoint"])

	ym, err := yaml.Marshal(config.CloudWatch{AwsEndpoint: "http://localhost:4566"})
	require.NoError(t, err)
	var ymap map[string]any
	require.NoError(t, yaml.Unmarshal(ym, &ymap))
	assert.Equal(t, "http://localhost:4566", ymap["aws_endpoint"])
}

// add_tags and replace_tags were removed: lenient decoders ignore them and
// strict decoders reject them.
func TestCloudWatchRemovedTagKeys(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"add_tags", "replace_tags"} {
		doc := "namespace: ns\n" + key + ":\n  a: b\n"

		var lenient config.CloudWatch
		require.NoError(t, yaml.Unmarshal([]byte(doc), &lenient))
		assert.Equal(t, config.CloudWatch{Namespace: "ns"}, lenient)

		var strict config.CloudWatch
		dec := yaml.NewDecoder(bytes.NewBufferString(doc))
		dec.KnownFields(true)
		assert.ErrorContains(t, dec.Decode(&strict), "field "+key+" not found")
	}
}

func TestMetricsGetDisabled(t *testing.T) {
	t.Parallel()

	yes, no := true, false
	assert.False(t, (&config.Metrics{}).GetDisabled())
	assert.False(t, (&config.Metrics{Disabled: &no}).GetDisabled())
	assert.True(t, (&config.Metrics{Disabled: &yes}).GetDisabled())
}
