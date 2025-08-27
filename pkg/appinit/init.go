package appinit

import (
	"io"
	"log"
	"os"
	"runtime/pprof"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/x/ctl"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xlog/logrotate"
	"github.com/effective-security/xlog/stackdriver"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/porto/pkg", "appinit")

// LogConfig defines config for logs
type LogConfig struct {
	LogStd         bool   `help:"output logs to stderr"`
	LogDebug       bool   `help:"output logs with debug info, such as filename:line"`
	LogPretty      bool   `help:"output logs in pretty format, with colors"`
	LogJSON        bool   `help:"output logs in JSON format"`
	LogStackdriver bool   `help:"output logs in GCP stackdriver format"`
	LogDir         string `help:"Store logs in folder"`
}

// Flags defines common flags
type Flags struct {
	Version ctl.VersionFlag `name:"version" help:"Print version information and quit" hidden:""`

	Cfg         string `short:"c" help:"load configuration file"`
	CfgOverride string `help:"configuration override file"`
	CPUProfile  string `help:"enable CPU profiling, specify a file to store CPU profiling info"`
	DryRun      bool   `help:"verify config etc, and do not start the service"`

	ClientCert      string `help:"Path to the client TLS cert file"`
	ClientKey       string `help:"Path to the client TLS key file"`
	ClientTrustedCA string `help:"Path to the client TLS trusted CA file"`
	Env             string `help:"Override environment value"`
	ServiceName     string `help:"Override service value"`
	Region          string `help:"Override region value"`
	Cluster         string `help:"Override cluster value"`

	WaitOnExit int `help:"Number of seconds to wait on exist"`
}

const (
	nullDevName = "/dev/null"
)

// Logs initializes app logs
func Logs(flags *LogConfig, serviceName string) (io.Closer, error) {
	var closer io.Closer
	var formatter xlog.Formatter
	if flags.LogDir != "" && flags.LogDir != nullDevName {
		_ = os.MkdirAll(flags.LogDir, 0755)
		var sink io.Writer
		if flags.LogStd {
			sink = os.Stderr
			formatter = xlog.NewPrettyFormatter(sink).Options(xlog.FormatWithColor)
		} else {
			// do not redirect stderr to our log files
			log.SetOutput(os.Stderr)
			if flags.LogPretty {
				formatter = xlog.NewPrettyFormatter(os.Stderr)
			} else {
				formatter = xlog.NewStringFormatter(os.Stderr)
			}
		}

		logRotate, err := logrotate.Initialize(flags.LogDir, serviceName, 10, 10, true, sink)
		if err != nil {
			logger.KV(xlog.ERROR,
				"reason", "logrotate",
				"folder", flags.LogDir,
				"err", err)
			return nil, errors.WithMessage(err, "failed to initialize log rotate")
		}
		closer = logRotate

	} else if flags.LogDir == nullDevName {
		formatter = xlog.NewNilFormatter()
	} else if flags.LogStackdriver {
		formatter = stackdriver.NewFormatter(os.Stderr, serviceName)
	} else if flags.LogJSON {
		formatter = xlog.NewJSONFormatter(os.Stderr)
	} else if flags.LogPretty {
		formatter = xlog.NewPrettyFormatter(os.Stderr).Options(xlog.FormatWithColor)
	} else {
		formatter = xlog.NewStringFormatter(os.Stderr)
	}

	xlog.SetFormatter(formatter)
	formatter.Options(xlog.FormatWithCaller)
	if flags.LogDebug {
		formatter.Options(xlog.FormatWithLocation)
	}
	logger.KV(xlog.INFO,
		"status", "service_starting",
		"args", os.Args)
	return closer, nil
}

// CPUProfiler starts CPU profiles
func CPUProfiler(file string) (io.Closer, error) {
	// create CPU Profiler
	if file != "" && file != nullDevName {
		cpuf, err := os.Create(file)
		if err != nil {
			return nil, errors.WithMessage(err, "unable to create CPU profile")
		}

		logger.KV(xlog.INFO, "starting_cpu_profiling", file)

		_ = pprof.StartCPUProfile(cpuf)
		return &cpuProfileCloser{file: file}, nil
	}
	return nil, nil
}
