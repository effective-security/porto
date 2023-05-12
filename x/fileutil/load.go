package fileutil

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
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
		f, err := os.ReadFile(fn)
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
		err := os.WriteFile(fn, []byte(value), 0644)
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

// Unmarshal JSON or YAML file to an interface
func Unmarshal(file string, v interface{}) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return errors.WithMessagef(err, "unable to read file")
	}

	if strings.HasSuffix(file, ".json") {
		err = json.Unmarshal(b, v)
		if err != nil {
			return errors.WithMessagef(err, "unable parse JSON: %s", file)
		}
	} else {
		err = yaml.Unmarshal(b, v)
		if err != nil {
			return errors.WithMessagef(err, "unable parse YAML: %s", file)
		}
	}
	return nil
}

// Marshal saves object to file
func Marshal(fn string, value interface{}) error {
	var data []byte
	var err error
	if strings.HasSuffix(fn, ".json") {
		data, err = json.MarshalIndent(value, "", "  ")
	} else {
		data, err = yaml.Marshal(value)
	}

	if err != nil {
		return errors.WithMessage(err, "failed to encode")
	}

	return os.WriteFile(fn, data, os.ModePerm)
}
