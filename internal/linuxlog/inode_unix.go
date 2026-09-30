//go:build !windows

package linuxlog

import (
	"os"
	"syscall"
)

// inode identifies a file independently of its name, so a rotated log can
// be found again.
func inode(_ string, fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
