// Package appinit wires common service start-up concerns: logging setup,
// the metrics pipeline and optional CPU profiling. It defines the Flags and
// LogConfig structs (tagged for github.com/alecthomas/kong CLI parsing) that
// services embed in their command line definitions.
//
// Each initializer returns an io.Closer (possibly nil) that the caller should
// close on shutdown, typically in reverse order:
//
//	logCloser, err := appinit.Logs(&flags.LogConfig, "myservice")
//	if err != nil {
//		return err
//	}
//	if logCloser != nil {
//		defer logCloser.Close()
//	}
//
//	prof, err := appinit.CPUProfiler(flags.CPUProfile) // nil closer when empty
//	if err != nil {
//		return err
//	}
//	if prof != nil {
//		defer prof.Close()
//	}
//
//	mc, err := appinit.Metrics(&cfg.Metrics, "myservice", "cluster-1", version, commit, myMetrics)
//	if err != nil {
//		return err
//	}
//	if mc != nil {
//		defer mc.Close()
//	}
//
// Metrics and Logs mutate process-global state (xlog formatter, the global
// metrics sink, the default Prometheus registry) and are meant to be called
// once per process. Metrics also registers an xlog error hook that counts
// logged errors in metricskey.HealthLogErrors.
// Prometheus binds synchronously, returns bind errors to the caller, and uses
// bounded HTTP read deadlines. Closing the metrics closer stops its endpoint,
// the runtime stats collector and the CloudWatch publisher, after the
// publisher's final publish.
package appinit
