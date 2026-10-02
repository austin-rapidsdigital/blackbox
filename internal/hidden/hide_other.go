//go:build !windows

package hidden

import "os/exec"

func hide(*exec.Cmd) {}
