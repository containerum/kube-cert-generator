package main

import (
	"io"
	"io/ioutil"
	"os"
)

func createFileIfNotExist(path string, overwrite bool) (io.Writer, error) {
	fileInfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		return os.Create(path)
	}
	if err != nil {
		return nil, err
	}
	if fileInfo.Size() > 0 && !overwrite {
		return ioutil.Discard, nil
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	return os.Create(path)
}

func createDirIfNotExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, os.ModePerm)
	}
	return nil
}
