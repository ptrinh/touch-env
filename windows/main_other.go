//go:build !windows

package main

import (
	"fmt"
	"os"
)

// The Windows touchenv only runs on Windows; on a Mac, touchenv is ../touchenv.swift. This file keeps
// `go build ./...` and `go vet ./...` working on other systems for the portable tests.
func main() {
	fmt.Fprintln(os.Stderr, "touchenv: this is the Windows build; build it with GOOS=windows")
	os.Exit(1)
}
