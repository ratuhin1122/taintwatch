//go:build !linux && !darwin

package state

import "os"

func supportedPlatform() error                   { return ErrUnsupportedPlatform }
func openNoFollow(string, int) (*os.File, error) { return nil, ErrUnsupportedPlatform }
func tryLock(*os.File) error                     { return ErrUnsupportedPlatform }
func unlock(*os.File) error                      { return ErrUnsupportedPlatform }
