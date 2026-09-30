// Package share reaches the collector's inbox when it is on another
// computer: a Windows share (\\server\share) or, on Linux, an SMB share
// (//server/share) that Blackbox mounts for itself.
package share

import (
	"path/filepath"
	"strings"
)

// Root returns the \\server\share (or //server/share) part of a path on a
// share, and the folder within it.
func Root(p string) (root, rest string) {
	sep := `\`
	if strings.HasPrefix(p, "//") {
		sep = "/"
	}
	parts := strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) < 2 {
		return p, ""
	}
	return sep + sep + parts[0] + sep + parts[1], strings.Join(parts[2:], sep)
}

// SplitUser separates DOMAIN\user or user@domain into its parts.
func SplitUser(u string) (domain, user string) {
	if i := strings.IndexByte(u, '\\'); i >= 0 {
		return u[:i], u[i+1:]
	}
	if i := strings.LastIndexByte(u, '@'); i >= 0 {
		return u[i+1:], u[:i]
	}
	return "", u
}

// SecretFile is where the share password is kept, in the data folder
// (readable only by administrators/root).
func SecretFile(dataDir string) string { return filepath.Join(dataDir, "share-credential") }
