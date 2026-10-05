package share

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/casea1/blackbox/internal/config"
)

// Why says, in a few words, why the collector's folder dest can't be used
// (L6): the error reaching it ("transport endpoint is not connected"),
// that nothing is mounted there, and on Linux the share it should be and
// the mount's last error from the journal ("No route to host",
// "Permission denied (publickey)").
func Why(cfg *config.Config, dest string) string {
	var parts []string
	fi, err := os.Stat(dest)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		parts = append(parts, "the folder does not exist")
	case err != nil:
		parts = append(parts, plainErr(err))
	case !fi.IsDir():
		parts = append(parts, "it is a file, not a folder")
	case !mounted(dest):
		parts = append(parts, "nothing is mounted there")
	default:
		parts = append(parts, "it is reachable, but it is not a Blackbox inbox (no BLACKBOX-INBOX.txt)")
	}
	source, last := mountInfo(cfg, dest)
	if source != "" {
		parts = append(parts, "share "+source)
	}
	if last != "" {
		parts = append(parts, "last mount error: "+last)
	}
	return strings.Join(parts, "; ")
}

// plainErr is an error without the path in it.
func plainErr(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	if errors.Is(err, syscall.ENOTCONN) {
		return "the mount is not connected (transport endpoint is not connected)"
	}
	if errors.Is(err, fs.ErrPermission) {
		return "access denied"
	}
	return err.Error()
}

// mounted reports whether something is mounted at dir (its device differs
// from its parent's). Where that can't be told, it says yes.
func mounted(dir string) bool {
	return deviceOf(dir) != deviceOf(filepath.Dir(filepath.Clean(dir))) || deviceOf(dir) == 0
}
