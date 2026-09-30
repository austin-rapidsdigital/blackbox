//go:build !windows && !linux

package install

import (
	"errors"
	"os"
)

var errLinux = errors.New("install is supported on Windows and Linux; on this system use `blackbox report` with exported log files")

// ProgramPath is where install copies the executable.
func ProgramPath() string { return "/usr/local/bin/blackbox" }

// Install is only available on Windows and Linux.
func Install(Options) error { return errLinux }

// Uninstall is only available on Windows and Linux.
func Uninstall(func(string, ...any)) error { return errLinux }

func afterReportDirChange(func(string, ...any)) error { return nil }

func restrictDir(dir string) error { return os.Chmod(dir, 0o700) }

// RequireAdmin is not needed where Blackbox cannot be installed.
func RequireAdmin() error { return errLinux }
