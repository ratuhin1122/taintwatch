//go:build !linux && !darwin

package policy

import (
	"fmt"
	"os"
)

func openPolicy(file string) (*os.File, error) {
	info, e := os.Lstat(file)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("policy must be a regular file")
	}
	return os.Open(file)
}
