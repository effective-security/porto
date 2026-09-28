package config

import (
	"time"

	"github.com/effective-security/porto/xhttp/limits"
)

// Metrics specifies the metrics pipeline configuration for appinit.Metrics.
type Metrics struct {
	// Disabled turns the pipeline off when true; nil means enabled.
	Disabled *bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`

	// Provider is a comma-separated list of sinks: prometheus, cloudwatch, inmem.
	// Empty disables metrics.
	Provider string `json:"provider,omitempty" yaml:"provider,omitempty"`

	// Prefix specifies the prefix added to all metrics
	Prefix string `json:"prefix,omitempty" yaml:"prefix,omitempty"`

	// PrefixForNumberLabels specifies a prefix to add to tag values that are 64-bit numbers
	PrefixForNumberLabels string `json:"prefix_for_number_labels,omitempty" yaml:"prefix_for_number_labels,omitempty"`

	// Prometheus provider config; required when Provider includes "prometheus".
	Prometheus *Prometheus `json:"prometheus,omitempty" yaml:"prometheus,omitempty"`

	// EnableRuntimeMetrics enables Go runtime metrics collection.
	EnableRuntimeMetrics bool `json:"runtime_metrics,omitempty" yaml:"runtime_metrics,omitempty"`

	// CloudWatch provider config; required when Provider includes "cloudwatch".
	CloudWatch *CloudWatch `json:"cloudwatch" yaml:"cloudwatch"`

	// GlobalTags lists tags added to every metric; supported names are
	// "service", "cluster_id" and "node" (value from $NODE_NAME).
	GlobalTags []string `json:"global_tags,omitempty" yaml:"global_tags,omitempty"`

	// AllowedPrefixes specifies a list of metric prefixes to allow, with '.' as the separator
	AllowedPrefixes []string `json:"allowed_prefixes,omitempty" yaml:"allowed_prefixes,omitempty"`
	// BlockedPrefixes specifies a list of metric prefixes to block, with '.' as the separator
	BlockedPrefixes []string `json:"blocked_prefixes,omitempty" yaml:"blocked_prefixes,omitempty"`
}

// GetDisabled reports whether Disabled is set to true.
func (c *Metrics) GetDisabled() bool {
	return c.Disabled != nil && *c.Disabled
}

// Prometheus configures the Prometheus sink.
type Prometheus struct {
	// Addr, when set, is the listen address for the /metrics HTTP endpoint.
	Addr string `json:"addr,omitempty" yaml:"addr,omitempty"`
	// Expiration is the duration a metric is valid for, after which it will be
	// untracked. If the value is zero, a default expiration applied
	Expiration time.Duration `json:"expiration,omitempty" yaml:"expiration,omitempty"`
	// Timeouts configures HTTP read deadlines; zero fields select shared defaults.
	Timeouts limits.Timeouts `json:"timeouts,omitempty" yaml:"timeouts,omitempty"`
	// MaxRequestBody limits HTTP request bytes; zero uses the shared default,
	// and a negative value disables it.
	MaxRequestBody int64 `json:"max_request_body,omitempty" yaml:"max_request_body,omitempty"`
}

// CloudWatch configures the CloudWatch sink. AdditionalTags and ReplaceTags
// are parsed but not currently applied by appinit.Metrics.
type CloudWatch struct {
	// AwsRegion where the service is deployed.
	AwsRegion string `json:"aws_region" yaml:"aws_region"`

	// AwsEndpoint is the optional AWS endpoint to use
	AwsEndpoint string

	// Namespace specifies CloudWatch namespace to push metrics and logs to.
	Namespace string `json:"namespace" yaml:"namespace"`

	// PublishInterval specifies the publish interval.
	PublishInterval time.Duration `json:"publish_interval" yaml:"publish_interval"`

	// AdditionalTags specifies additional tags/labels to send to CloudWatch
	AdditionalTags map[string]string `json:"add_tags" yaml:"add_tags"`

	// ReplaceTags tags with the provided label.
	// This allows for aggregating metrics across dimensions so we can set CloudWatch Alarms on the metrics
	ReplaceTags map[string]string `json:"replace_tags" yaml:"replace_tags"`

	// WithSampleCount specifies whether to include the sample count in the metric
	// it adds _count, _avg , _sum
	WithSampleCount bool `json:"with_sample_count" yaml:"with_sample_count"`
}
