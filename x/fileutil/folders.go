package fileutil

import (
	"os"

	"github.com/pkg/errors"
)

// FolderExists ensures that folder exists
func FolderExists(dir string) error {
	if dir == "" {
		return errors.Errorf("invalid parameter: dir")
	}

	stat, err := os.Stat(dir)
	if err != nil {
		return errors.WithStack(err)
	}

	if !stat.IsDir() {
		return errors.Errorf("not a folder: %q", dir)
	}

	return nil
}

// FileExists ensures that file exists
func FileExists(file string) error {
	if file == "" {
		return errors.Errorf("invalid parameter: file")
	}

	stat, err := os.Stat(file)
	if err != nil {
		return errors.WithStack(err)
	}

	if stat.IsDir() {
		return errors.Errorf("not a file: %q", file)
	}

	return nil
}
