// Package hidden runs other programs without a console window.
//
// Setup and the status icon are windowed programs: a console program they
// start (schtasks, icacls, PowerShell) would otherwise open a console
// window of its own for a moment. Output is still captured as usual.
package hidden

import "os/exec"

// Command is exec.Command, with no console window on Windows.
func Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	hide(cmd)
	return cmd
}
