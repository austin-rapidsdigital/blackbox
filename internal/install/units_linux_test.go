//go:build linux

package install

import (
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/config"
)

// L8: a sender to a folder the site mounted (sshfs) never names that
// folder in the run unit, so a dead mount cannot stop collection: the run
// only queues, and blackbox-send.service delivers, remounting first.
func TestSendUnitSeparate(t *testing.T) {
	cfg := &config.Config{DataDir: "/var/lib/blackbox", SendTo: "/mnt/blackbox inbox"}
	svc := serviceFor("/usr/local/bin/blackbox", cfg)
	if strings.Contains(svc, "/mnt/blackbox") || !strings.Contains(svc, "ExecStart=/usr/local/bin/blackbox run --no-deliver") ||
		!strings.Contains(svc, "Wants=blackbox-send.service") {
		t.Errorf("run unit:\n%s", svc)
	}
	send := systemdSendService("/usr/local/bin/blackbox", cfg.SendTo)
	for _, want := range []string{`ExecStartPre=-+/bin/mount "/mnt/blackbox inbox"`, "ExecStart=/usr/local/bin/blackbox send\n", "After=blackbox.service", "ProtectSystem=full"} {
		if !strings.Contains(send, want) {
			t.Errorf("send unit missing %q:\n%s", want, send)
		}
	}
	for _, unit := range []string{send, shutdownFor("/usr/local/bin/blackbox", cfg)} {
		if strings.Contains(unit, "ReadWritePaths") || strings.Contains(unit, "/mnt/blackbox") && !strings.Contains(unit, "/bin/mount") {
			t.Errorf("unit names the collector's folder:\n%s", unit)
		}
	}
	// An SMB share Blackbox mounts itself: delivered from the run, as before.
	cfg.SendTo = "//collector/BlackboxInbox"
	if svc := serviceFor("/usr/local/bin/blackbox", cfg); strings.Contains(svc, "--no-deliver") || strings.Contains(svc, "blackbox-send") {
		t.Errorf("SMB run unit:\n%s", svc)
	}
}
