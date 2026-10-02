//go:build !windows

package gui

import "errors"

var errWindows = errors.New("the setup window and the status icon are Windows only; use `blackbox install`")

// Setup is Windows only.
func Setup(version string, selftest bool) error { return errWindows }

// Tray is Windows only.
func Tray(version string, selftest bool) error { return errWindows }

// Launched is false outside Windows.
func Launched() bool { return false }

// AttachConsole does nothing outside Windows.
func AttachConsole() {}
