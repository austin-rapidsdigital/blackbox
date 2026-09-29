//go:build !windows

package winevt

// GetLogSettings is only available on Windows.
func GetLogSettings(string) (LogSettings, error) { return LogSettings{}, errUnsupported }
