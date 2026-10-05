//go:build !windows

package share

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/casea1/blackbox/internal/config"
)

func deviceOf(p string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		return 0
	}
	return uint64(st.Dev)
}

// mountInfo is the share meant to be mounted at dest (from Blackbox's own
// SMB setting, or /etc/fstab) and the last error its mount unit logged.
func mountInfo(cfg *config.Config, dest string) (source, last string) {
	unit := ""
	if config.IsShare(cfg.SendTo) {
		source = cfg.SendTo
	} else if b, err := os.ReadFile("/etc/fstab"); err == nil {
		source = fstabSource(string(b), dest)
	}
	if out, err := exec.Command("systemd-escape", "--path", "--suffix=mount", filepath.Clean(dest)).Output(); err == nil {
		unit = strings.TrimSpace(string(out))
	}
	if unit != "" {
		if out, err := exec.Command("journalctl", "-u", unit, "-n", "40", "-o", "cat", "--no-pager").Output(); err == nil {
			last = lastMountError(string(out))
		}
	}
	return source, last
}

// fstabSource is the device or share /etc/fstab mounts at dir.
func fstabSource(fstab, dir string) string {
	dir = filepath.Clean(dir)
	for _, l := range strings.Split(fstab, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && !strings.HasPrefix(f[0], "#") && filepath.Clean(strings.ReplaceAll(f[1], `\040`, " ")) == dir {
			return f[0]
		}
	}
	return ""
}

// mountCauses are the words sshfs and mount.cifs use for why a mount
// failed; mountFailed are systemd's own, used when none of those is there.
var (
	mountCauses = []string{"No route to host", "Permission denied", "Connection refused", "Connection timed out",
		"Connection reset", "Host is down", "Name or service not known", "Could not resolve", "Host key verification failed"}
	mountFailed = []string{"error", "Error", "failed", "Failed"}
)

// lastMountError is the last line of a mount unit's log that says why it
// failed.
func lastMountError(log string) string {
	lines := strings.Split(strings.TrimSpace(log), "\n")
	for _, words := range [][]string{mountCauses, mountFailed} {
		for i := len(lines) - 1; i >= 0; i-- {
			l := strings.TrimSpace(lines[i])
			for _, w := range words {
				if strings.Contains(l, w) {
					return l
				}
			}
		}
	}
	return ""
}
