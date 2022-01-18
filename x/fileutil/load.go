package fileutil

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"
)

const (
	// FileSource specifies to load config from a file
	FileSource = "file://"
	// EnvSource specifies to load config from an environment variable
	EnvSource = "env://"
)

// LoadConfigWithSchema returns a configuration loaded from file:// or env://
// If config does not start with file:// or env://, then the value is returned as is
func LoadConfigWithSchema(config string) (string, error) {
	if strings.HasPrefix(config, FileSource) {
		fn := strings.TrimPrefix(config, FileSource)
		f, err := ioutil.ReadFile(fn)
		if err != nil {
			return config, errors.WithStack(err)
		}
		// file content
		config = string(f)
	} else if strings.HasPrefix(config, EnvSource) {
		env := strings.TrimPrefix(config, EnvSource)
		// ENV content
		config = os.Getenv(env)
		if config == "" {
			return "", errors.Errorf("Environment variable %q is not set", env)
		}
	}

	return config, nil
}

// SaveConfigWithSchema saves configuration to file:// or env://
func SaveConfigWithSchema(path, value string) error {
	if strings.HasPrefix(path, FileSource) {
		fn := strings.TrimPrefix(path, FileSource)
		err := ioutil.WriteFile(fn, []byte(value), 0644)
		if err != nil {
			return errors.WithStack(err)
		}
	} else if strings.HasPrefix(path, EnvSource) {
		env := strings.TrimPrefix(path, EnvSource)
		// ENV content
		err := os.Setenv(env, value)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}
