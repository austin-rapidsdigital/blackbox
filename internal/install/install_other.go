//go:build !windows

package install

import "errors"

var errLinux = errors.New("install on Linux arrives with Linux log collection (next milestone); on this system you can use `blackbox report --xml` to report on exported Windows logs")

// ProgramPath is where install copies the executable.
func ProgramPath() string { return "/usr/local/bin/blackbox" }

// Install is not yet available off Windows.
func Install(Options) error { return errLinux }

// Uninstall is not yet available off Windows.
func Uninstall(func(string, ...any)) error { return errLinux }
