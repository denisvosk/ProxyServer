//go:build !windows

package main

import "os"

func makeSecureDirectory(path string) error { return os.Mkdir(path, 0700) }
