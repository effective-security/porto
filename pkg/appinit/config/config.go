package config

import "time"

// Metrics specifies the metrics pipeline configuration
type Metrics struct {
	// Disabled specifies if the metrics provider is disabled
	Disabled *bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`

	// Provider specifies the metrics provider: prometheus|inmem
	Provider string `json:"provider,omitempty" yaml:"provider,omitempty"`

	// Prefix specifies the prefix added to all metrics
	Prefix string `json:"prefix,omitempty" yaml:"prefix,omitempty"`

	// Prometheus provider config
	Prometheus *Prometheus `json:"prometheus,omitempty" yaml:"prometheus,omitempty"`

	EnableRuntimeMetrics bool `json:"runtime_metrics,omitempty" yaml:"runtime_metrics,omitempty"`

	CloudWatch *CloudWatch `json:"cloudwatch" yaml:"cloudwatch"`

	GlobalTags []string `json:"global_tags,omitempty" yaml:"global_tags,omitempty"`

	// AllowedPrefixes specifies a list of metric prefixes to allow, with '.' as the separator
	AllowedPrefixes []string `json:"allowed_prefixes,omitempty" yaml:"allowed_prefixes,omitempty"`
	// BlockedPrefixes specifies a list of metric prefixes to block, with '.' as the separator
	BlockedPrefixes []string `json:"blocked_prefixes,omitempty" yaml:"blocked_prefixes,omitempty"`
}

// GetDisabled specifies if the metrics provider is disabled
func (c *Metrics) GetDisabled() bool {
	return c.Disabled != nil && *c.Disabled
}

// Prometheus provider config
type Prometheus struct {
	Addr string `json:"addr,omitempty" yaml:"addr,omitempty"`
	// Expiration is the duration a metric is valid for, after which it will be
	// untracked. If the value is zero, a default expiration applied
	Expiration time.Duration `json:"expiration,omitempty" yaml:"expiration,omitempty"`
}

// CloudWatch specifies the Prometheus settings for CloudWatch
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
