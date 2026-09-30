package linuxlog

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// Users maps numeric user IDs to names, from /etc/passwd.
type Users map[int]string

// LoadUsers reads an /etc/passwd-format file. A missing file gives an
// empty map (IDs are then shown as "uid 1000" unless the audit log is in
// ENRICHED format, which records names itself).
func LoadUsers(path string) Users {
	f, err := os.Open(path)
	if err != nil {
		return Users{}
	}
	defer f.Close()
	return ParseUsers(f)
}

// ParseUsers parses passwd-format text.
func ParseUsers(r io.Reader) Users {
	u := Users{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if id, err := strconv.Atoi(f[2]); err == nil {
			u[id] = f[0]
		}
	}
	return u
}

// Name returns the account name for a uid string ("" for unset).
func (u Users) Name(uid string) string {
	switch uid {
	case "", "4294967295", "-1", "?", "unset":
		return ""
	}
	id, err := strconv.Atoi(uid)
	if err != nil {
		return uid
	}
	if n, ok := u[id]; ok {
		return n
	}
	if id == 0 {
		return "root"
	}
	return "uid " + uid
}
