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

// LogConfig holds the logging command line flags consumed by Logs.
// The help tags are for kong. Precedence: LogDir (file rotation) >
// "/dev/null" (discard) > LogStackdriver > LogJSON > LogPretty > plain text.
type LogConfig struct {
	LogStd         bool   `help:"output logs to stderr"`
	LogDebug       bool   `help:"output logs with debug info, such as filename:line"`
	LogPretty      bool   `help:"output logs in pretty format, with colors"`
	LogJSON        bool   `help:"output logs in JSON format"`
	LogStackdriver bool   `help:"output logs in GCP stackdriver format"`
	LogDir         string `help:"Store logs in folder"`
}

// Flags holds the command line flags shared by services (kong tags):
// config file paths, CPU profiling output, dry-run, client TLS files and
// environment/service/region/cluster overrides.
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

// Logs configures the process-global xlog formatter from flags and logs a
// "service_starting" line with os.Args. When LogDir is set, log rotation is
// initialized under LogDir/<serviceName>.log and the returned closer must be
// closed at shutdown; otherwise the closer is nil. LogDir "/dev/null"
// discards all output.
func Logs(flags *LogConfig, serviceName string) (io.Closer, error) {
	var closer io.Closer
	var formatter xlog.Formatter
	if flags.LogDir != "" && flags.LogDir != nullDevName {
		_ = os.MkdirAll(flags.LogDir, 0755)
		var sink io.Writer
		if flags.LogStd {
			sink = os.Stderr
		} else {
			// do not redirect stderr to our log files
			log.SetOutput(os.Stderr)
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
		// logrotate.Initialize installed the rotating-file formatter; keep it
		// (calling SetFormatter here would replace it and leave the file empty)
		// and only adjust its options.
		formatter = xlog.GetFormatter()
	} else {
		switch {
		case flags.LogDir == nullDevName:
			formatter = xlog.NewNilFormatter()
		case flags.LogStackdriver:
			formatter = stackdriver.NewFormatter(os.Stderr, serviceName)
		case flags.LogJSON:
			formatter = xlog.NewJSONFormatter(os.Stderr)
		case flags.LogPretty:
			formatter = xlog.NewPrettyFormatter(os.Stderr).Options(xlog.FormatWithColor(true))
		default:
			formatter = xlog.NewStringFormatter(os.Stderr)
		}
		xlog.SetFormatter(formatter)
	}

	formatter.Options(xlog.FormatWithCaller(true))
	if flags.LogDebug {
		formatter.Options(xlog.FormatWithLocation(true))
	}
	logger.KV(xlog.INFO,
		"status", "service_starting",
		"args", os.Args)
	return closer, nil
}

// CPUProfiler starts a CPU profile written to file and returns a closer that
// stops it. It returns a nil closer and nil error when file is empty or
// "/dev/null". The profile file handle is not closed by the closer.
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
