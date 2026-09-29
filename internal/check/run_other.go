//go:build !windows

package check

// Supported reports whether the live check works on this OS.
const Supported = false

// Run is not yet implemented off Windows (Linux auditd checks come with
// Linux collection).
func Run() []Result { return nil }
