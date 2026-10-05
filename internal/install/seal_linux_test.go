//go:build linux

package install

import (
	"strings"
	"testing"
)

// N1: the share is mounted encrypted, and a collector that can't encrypt
// is explained.
func TestShareMountIsEncrypted(t *testing.T) {
	if !strings.Contains(mountUnit("//COLLECTOR/BlackboxInbox"), ",seal,") {
		t.Error("mount unit without seal")
	}
	err := mountError("mount error(95): Operation not supported\nRefer to the mount.cifs(8) manual page")
	if err == nil || !strings.Contains(err.Error(), "encrypted connection") || !strings.Contains(err.Error(), "-EncryptData $true") {
		t.Errorf("error: %v", err)
	}
	if err := mountError("mount error(13): Permission denied"); strings.Contains(err.Error(), "encrypt") {
		t.Errorf("wrong password explained as encryption: %v", err)
	}
}
