//go:build !windows

package share

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/config"
)

// L6: why the collector's folder can't be used, with the share and the
// mount's own error.
func TestWhy(t *testing.T) {
	fstab := "# comment\nUUID=x / ext4 defaults 0 1\nbbsend@COLLECTOR:/C:/BlackboxInbox  /mnt/blackbox-inbox  fuse.sshfs  _netdev,reconnect 0 0\n"
	if got := fstabSource(fstab, "/mnt/blackbox-inbox/"); got != "bbsend@COLLECTOR:/C:/BlackboxInbox" {
		t.Errorf("fstab source %q", got)
	}
	log := "Mounting mnt-blackbox\\x2dinbox.mount...\nssh: connect to host COLLECTOR port 22: No route to host\nmnt-blackbox\\x2dinbox.mount: Mount process exited, code=exited, status=1/FAILURE\nmnt-blackbox\\x2dinbox.mount: Failed with result 'exit-code'."
	if got := lastMountError(log); got != "ssh: connect to host COLLECTOR port 22: No route to host" {
		t.Errorf("mount error %q", got)
	}
	if got := lastMountError("x.mount: Failed with result 'exit-code'."); !strings.Contains(got, "Failed") {
		t.Errorf("generic error %q", got)
	}
	dir := t.TempDir()
	cfg := &config.Config{SendTo: filepath.Join(dir, "missing")}
	if got := Why(cfg, cfg.SendTo); !strings.HasPrefix(got, "the folder does not exist") {
		t.Errorf("missing: %q", got)
	}
	os.Mkdir(filepath.Join(dir, "empty"), 0o755)
	if got := Why(cfg, filepath.Join(dir, "empty")); !strings.HasPrefix(got, "nothing is mounted there") {
		t.Errorf("empty: %q", got)
	}
}
