//go:build !windows

package winevt

import "errors"

// Supported reports whether live collection works on this OS.
const Supported = false

var errUnsupported = errors.New("reading live Windows event logs is only possible on Windows (use exported XML instead)")

// ErrChannelNotFound means the log does not exist or is disabled.
var ErrChannelNotFound = errors.New("log not found or not enabled")

// ReadChannel is only available on Windows.
func ReadChannel(string, uint64, func(*Raw) error) error { return errUnsupported }

// Edges is only available on Windows.
func Edges(string) (*Raw, *Raw, error) { return nil, nil, errUnsupported }

// ReadFile (.evtx) is only available on Windows.
func ReadFile(string, func(*Raw) error) error { return errUnsupported }

// LookupSID is only available on Windows.
func LookupSID(string) string { return "" }

// DevicePathMapper is only available on Windows.
func DevicePathMapper() func(string) string { return nil }
