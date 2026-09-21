// Package config defines the metrics pipeline configuration consumed by
// appinit.Metrics. The struct is tagged for JSON and YAML:
//
//	metrics:
//	  disabled: false
//	  provider: prometheus,cloudwatch   # comma-separated: prometheus | cloudwatch | inmem
//	  prefix: myservice
//	  prefix_for_number_labels: n_
//	  runtime_metrics: true
//	  global_tags: [service, cluster_id, node]
//	  allowed_prefixes: [myservice.]
//	  blocked_prefixes: []
//	  prometheus:
//	    addr: :9090
//	    expiration: 5m
//	  cloudwatch:
//	    aws_region: us-west-2
//	    namespace: MyService
//	    publish_interval: 1m
//	    with_sample_count: true
//
// The "cloudwatch" key has no omitempty tag and is always emitted on
// marshal. CloudWatch.AwsEndpoint has no tags and therefore uses the
// encoder's default key ("AwsEndpoint" in JSON, "awsendpoint" in YAML).
package config
