package install

import (
	"fmt"
	"os"
)

// kept is a program set aside by an upgrade: path is where it ran from,
// old the name it was renamed to.
type kept struct{ path, old string }

// swapIn puts a new program at path. A running program can't be
// overwritten but can be renamed, so the one in place is renamed aside
// first; the name it was given is returned ("" when there was none), so a
// rollback puts back exactly that file.
func swapIn(path string, data []byte) (old string, err error) {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err == nil {
		old = oldName(path)
		if err := os.Rename(path, old); err != nil {
			os.Remove(tmp)
			return "", err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return old, err
	}
	return old, nil
}

// oldName is where a replaced program waits until the new one is checked.
// A previous .old still in use (an icon that hasn't restarted yet) is
// left alone and the next free name is used.
func oldName(p string) string {
	for i := 0; ; i++ {
		n := p + ".old"
		if i > 0 {
			n = fmt.Sprintf("%s.old%d", p, i)
		}
		if _, err := os.Stat(n); os.IsNotExist(err) {
			return n
		}
	}
}

// rollBack puts back the programs an upgrade set aside, and says whether
// any were.
func rollBack(ks []kept) bool {
	restored := false
	for _, k := range ks {
		if k.old == "" {
			continue
		}
		os.Remove(k.path)
		if os.Rename(k.old, k.path) == nil {
			restored = true
		}
	}
	return restored
}
