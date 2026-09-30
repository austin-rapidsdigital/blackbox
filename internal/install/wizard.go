package install

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/config"
)

// Answers are the settings chosen during setup.
type Answers struct {
	Site         string
	ReportEvery  string        // daily | weekly | monthly
	ReportDir    string        // "" = the default reports folder
	CollectEvery time.Duration // how often the schedule runs
}

// ErrCancelled means the person chose not to go ahead.
var ErrCancelled = errors.New("setup cancelled; nothing was changed")

// wizard asks setup questions on a console.
type wizard struct {
	in  *bufio.Reader
	out io.Writer
	// dirExists and dirWritable are replaceable for tests.
	dirExists   func(string) (bool, error)
	dirWritable func(string) error
}

// Wizard asks the setup questions, offering cur as the defaults (the
// current settings on a re-install), checks each answer as it is given,
// and asks for confirmation. defaultReports is the folder used when
// ReportDir is empty.
func Wizard(in io.Reader, out io.Writer, cur Answers, defaultReports string, reinstall bool) (Answers, error) {
	w := &wizard{in: bufio.NewReader(in), out: out, dirExists: dirExists, dirWritable: CheckWritable}
	return w.run(cur, defaultReports, reinstall)
}

func dirExists(p string) (bool, error) {
	fi, err := os.Stat(p)
	switch {
	case os.IsNotExist(err):
		return false, nil
	case err != nil:
		return false, err
	case !fi.IsDir():
		return false, fmt.Errorf("%s is a file, not a folder", p)
	}
	return true, nil
}

func (w *wizard) printf(format string, a ...any) { fmt.Fprintf(w.out, format, a...) }

// line reads one answer; io.EOF (no more input) cancels setup.
func (w *wizard) line() (string, error) {
	s, err := w.in.ReadString('\n')
	if err != nil && (s == "" || !errors.Is(err, io.EOF)) {
		if errors.Is(err, io.EOF) {
			return "", ErrCancelled
		}
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func (w *wizard) run(cur Answers, defaultReports string, reinstall bool) (Answers, error) {
	a := cur
	if a.ReportEvery == "" {
		a.ReportEvery = "weekly"
	}
	if a.CollectEvery == 0 {
		a.CollectEvery = time.Hour
	}
	title := "Blackbox setup"
	if reinstall {
		title = "Blackbox setup (already installed: your current settings are shown as the defaults)"
	}
	w.printf("\n%s\n%s\n", title, strings.Repeat("-", len(title)))
	w.printf("Press Enter to keep the value in [brackets].\n\n")

	// 1. Site name.
	w.printf("1. Site or system name, shown at the top of each report\n")
	if a.Site != "" {
		w.printf("   (type - to clear it)\n")
	}
	w.printf("   [%s]: ", orNone(a.Site))
	s, err := w.line()
	if err != nil {
		return a, err
	}
	switch {
	case s == "-":
		a.Site = "" // "-" clears it
	case s != "":
		a.Site = s
	}

	// 2. Report schedule.
	w.printf("\n2. How often should a report be produced?\n")
	every := []string{"daily", "weekly", "monthly"}
	labels := []string{"Daily   (each report covers one day, ending at midnight)",
		"Weekly  (Monday 00:00 to Monday 00:00)", "Monthly (1st to 1st)"}
	i, err := w.choose(labels, indexOf(every, a.ReportEvery))
	if err != nil {
		return a, err
	}
	a.ReportEvery = every[i]

	// 3. Report folder.
	w.printf("\n3. Where should reports be saved?\n")
	w.printf("   Use a folder you have locked down if you like; Blackbox only needs to write to it.\n")
	for {
		show := a.ReportDir
		if show == "" {
			show = defaultReports
		}
		w.printf("   [%s]: ", show)
		s, err := w.line()
		if err != nil {
			return a, err
		}
		if s == "" {
			s = show
		}
		s = strings.Trim(s, `"`)
		if s == defaultReports {
			a.ReportDir = ""
			break
		}
		if !config.IsAbs(s) {
			w.printf("   Please enter a full path, for example %s\n", exampleFolder())
			continue
		}
		ok, err := w.checkFolder(s)
		if err != nil {
			return a, err
		}
		if ok {
			a.ReportDir = s
			break
		}
	}

	// 4. Collection interval.
	w.printf("\n4. How often should events be collected from the logs?\n")
	ints := []time.Duration{time.Hour, 30 * time.Minute, 15 * time.Minute}
	labels = []string{"Every hour        (recommended)", "Every 30 minutes",
		"Every 15 minutes  (for busy systems whose logs fill up within a few hours)"}
	if indexOf(ints, a.CollectEvery) < 0 {
		ints = append(ints, a.CollectEvery)
		labels = append(labels, strings.ToUpper(EveryText(a.CollectEvery)[:1])+EveryText(a.CollectEvery)[1:]+"  (current setting)")
	}
	i, err = w.choose(labels, indexOf(ints, a.CollectEvery))
	if err != nil {
		return a, err
	}
	a.CollectEvery = ints[i]

	// Summary.
	dir := a.ReportDir
	if dir == "" {
		dir = defaultReports
	}
	w.printf("\nSummary\n")
	w.printf("   Site name:        %s\n", orNone(a.Site))
	w.printf("   Reports:          %s, saved in %s\n", a.ReportEvery, dir)
	w.printf("   Collect events:   %s\n", EveryText(a.CollectEvery))
	verb := "Install"
	if reinstall {
		verb = "Apply"
	}
	for {
		w.printf("\n%s these settings? (Y/n): ", verb)
		s, err := w.line()
		if err != nil {
			return a, err
		}
		switch strings.ToLower(s) {
		case "", "y", "yes":
			return a, nil
		case "n", "no":
			return a, ErrCancelled
		}
	}
}

// checkFolder reports whether a report folder is usable, offering to
// create it if it does not exist.
func (w *wizard) checkFolder(dir string) (bool, error) {
	exists, err := w.dirExists(dir)
	if err != nil {
		w.printf("   %v\n", err)
		return false, nil
	}
	if exists {
		if err := w.dirWritable(dir); err != nil {
			w.printf("   Blackbox cannot write to that folder (%v).\n   Choose another folder, or give administrators write access and try again.\n", err)
			return false, nil
		}
		return true, nil
	}
	for {
		w.printf("   That folder does not exist yet. Create it (administrators only)? (Y/n): ")
		s, err := w.line()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "", "y", "yes":
			return true, nil // created during install
		case "n", "no":
			return false, nil
		}
	}
}

// choose shows numbered options and returns the index picked.
func (w *wizard) choose(labels []string, def int) (int, error) {
	if def < 0 {
		def = 0
	}
	for i, l := range labels {
		w.printf("     %d) %s\n", i+1, l)
	}
	for {
		w.printf("   Choose 1-%d [%d]: ", len(labels), def+1)
		s, err := w.line()
		if err != nil {
			return 0, err
		}
		if s == "" {
			return def, nil
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(labels) {
			return n - 1, nil
		}
		w.printf("   Please enter a number from 1 to %d.\n", len(labels))
	}
}

func indexOf[T comparable](list []T, v T) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return -1
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func exampleFolder() string {
	if strings.HasPrefix(config.DefaultDataDir(), "/") {
		return "/srv/audit-reports"
	}
	return `D:\AuditReports`
}

// IsTerminal reports whether f is an interactive console, so setup can ask
// questions (and skips them when run from a script or deployment tool).
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// EveryText describes an interval: "every hour", "every 30 minutes".
func EveryText(d time.Duration) string {
	switch {
	case d == time.Hour:
		return "every hour"
	case d%time.Hour == 0:
		return fmt.Sprintf("every %d hours", int(d.Hours()))
	}
	return fmt.Sprintf("every %d minutes", int(d.Minutes()))
}
