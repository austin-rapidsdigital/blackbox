//go:build windows

package share

import "github.com/casea1/blackbox/internal/config"

// On Windows, a share's own error comes from connecting to it (Connect).
func deviceOf(string) uint64 { return 0 }

func mountInfo(*config.Config, string) (string, string) { return "", "" }
