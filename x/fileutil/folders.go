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

// SubfolderNames returns list of subfolders in provided folder
func SubfolderNames(folder string) ([]string, error) {
	var list []string

	f, err := os.Open(folder)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	dirs, err := f.ReadDir(-1)
	f.Close()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	for _, d := range dirs {
		if d.IsDir() {
			list = append(list, d.Name())
		}
	}

	return list, nil
}

// FileNames returns list of files in provided folder.
func FileNames(folder string) ([]string, error) {
	var list []string

	f, err := os.Open(folder)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	dirs, err := f.ReadDir(-1)
	f.Close()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	for _, d := range dirs {
		if !d.IsDir() {
			list = append(list, d.Name())
		}
	}

	return list, nil
}
