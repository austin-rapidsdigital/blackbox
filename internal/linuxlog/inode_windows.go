//go:build windows

package linuxlog

import "os"

// inode is not used on Windows (Linux logs are only followed on Linux).
func inode(os.FileInfo) uint64 { return 0 }
