package archive

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/winevt"
)

// export saves each event log Blackbox reads, for [from, to), as an .evtx
// file with wevtutil (the export Event Viewer's "Save events as" uses).
func export(tmp string, from, to time.Time) ([]Source, []string) {
	const ts = "2006-01-02T15:04:05.000Z"
	query := fmt.Sprintf("/q:*[System[TimeCreated[@SystemTime>='%s' and @SystemTime<'%s']]]",
		from.UTC().Format(ts), to.UTC().Format(ts))
	var sources []Source
	var notes []string
	for _, ch := range winevt.Channels {
		name := SafeName(ch) + ".evtx"
		path := filepath.Join(tmp, name)
		out, err := exec.Command(wevtutil(), "epl", ch, path, query, "/ow:true").CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if strings.Contains(strings.ToLower(msg), "could not be found") {
				notes = append(notes, ch+": not on this computer")
			} else {
				notes = append(notes, fmt.Sprintf("%s: could not be exported: %v %s", ch, err, msg))
			}
			continue
		}
		sources = append(sources, Source{Name: name, Source: ch, Path: path})
	}
	return sources, notes
}

func wevtutil() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return filepath.Join(root, "System32", "wevtutil.exe")
	}
	return "wevtutil.exe"
}
