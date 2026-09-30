//go:build !windows && !linux

package share

import "github.com/casea1/blackbox/internal/config"

// Destination returns the folder batches are delivered to.
func Destination(cfg *config.Config) (string, error) { return cfg.SendTo, nil }
