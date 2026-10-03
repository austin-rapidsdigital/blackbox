package check

import (
	"sort"
	"strings"
)

// auditRule is one audit rule, reduced to what it records, so that rules
// written differently (a rules file versus `auditctl -l` output, other key
// names, other syscall order) can be compared.
type auditRule struct {
	// watch is the file or folder a rule watches, normalised: from -w, or
	// from a path= or dir= condition. "-w /etc/passwd -p wa" and
	// "-a always,exit -F path=/etc/passwd -F perm=wa" are the same rule
	// (A12), and so are a -w on a folder and dir=.
	watch    string
	perm     string          // -p / perm= letters, sorted
	list     string          // -a always,exit
	arch     string          // arch=b64 | b32 | ""
	syscalls map[string]bool // -S names; empty = all
	filters  []string        // other -F and -C conditions, normalised and sorted
	raw      string
}

// normPath removes a trailing slash, as auditctl does when it lists rules.
func normPath(p string) string {
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// normValue makes equivalent field values equal: auditctl lists
// auid!=unset as auid!=-1 (or 4294967295).
func normValue(f string) string {
	for _, op := range []string{"!=", ">=", "<=", "=", ">", "<"} {
		if i := strings.Index(f, op); i > 0 {
			name, val := f[:i], f[i+len(op):]
			if val == "unset" || val == "4294967295" {
				val = "-1"
			}
			if name == "path" || name == "dir" {
				val = normPath(val)
			}
			return name + op + val
		}
	}
	return f
}

func sortedLetters(s string) string {
	b := []byte(s)
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
	return string(b)
}

// parseAuditRule reads one rule line. Control lines (-b, -e, -D, -f …) and
// comments return false.
func parseAuditRule(line string) (auditRule, bool) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 2 || strings.HasPrefix(f[0], "#") {
		return auditRule{}, false
	}
	r := auditRule{syscalls: map[string]bool{}, raw: strings.TrimSpace(line)}
	switch f[0] {
	case "-w":
		r.watch = normPath(f[1])
		r.list = "always,exit"
	case "-a", "-A":
		r.list = f[1]
	default:
		return auditRule{}, false
	}
	for i := 2; i < len(f); i++ {
		next := func() string {
			if i+1 < len(f) {
				i++
				return f[i]
			}
			return ""
		}
		switch f[i] {
		case "-k":
			next() // keys are labels, not what is recorded
		case "-p":
			r.perm = sortedLetters(next())
		case "-S":
			for _, s := range strings.Split(next(), ",") {
				if s != "" && s != "all" {
					r.syscalls[s] = true
				}
			}
		case "-F", "-C":
			v := normValue(next())
			switch {
			case strings.HasPrefix(v, "key="):
			case strings.HasPrefix(v, "arch="):
				r.arch = strings.TrimPrefix(v, "arch=")
			case strings.HasPrefix(v, "perm="):
				r.perm = sortedLetters(strings.TrimPrefix(v, "perm="))
			case strings.HasPrefix(v, "path=") || strings.HasPrefix(v, "dir="):
				_, r.watch, _ = strings.Cut(v, "=")
			default:
				r.filters = append(r.filters, v)
			}
		}
	}
	sort.Strings(r.filters)
	if r.watch != "" {
		// A watch records the file whatever the architecture, and a path
		// rule is written with or without one.
		r.arch = ""
		if r.list == "exit,always" {
			r.list = "always,exit"
		}
	}
	return r, true
}

// covers reports whether rule x records everything rule r records (for the
// same kind of rule): the same target and conditions, and every syscall.
func (x auditRule) covers(r auditRule) bool {
	if x.watch != r.watch || x.list != r.list || x.arch != r.arch {
		return false
	}
	if !containsAll(x.perm, r.perm) {
		return false
	}
	if strings.Join(x.filters, " ") != strings.Join(r.filters, " ") {
		return false
	}
	if len(x.syscalls) == 0 {
		return true // all syscalls
	}
	for s := range r.syscalls {
		if !x.syscalls[s] {
			return false
		}
	}
	return len(r.syscalls) > 0
}

func containsAll(have, want string) bool {
	for _, c := range want {
		if !strings.ContainsRune(have, c) {
			return false
		}
	}
	return true
}

// coveredBy reports whether the loaded rules already record everything r
// records, possibly split over several rules (e.g. one per syscall).
func (r auditRule) coveredBy(loaded []auditRule) bool {
	for _, x := range loaded {
		if x.covers(r) {
			return true
		}
	}
	if len(r.syscalls) < 2 {
		return false
	}
	for s := range r.syscalls {
		one := r
		one.syscalls = map[string]bool{s: true}
		ok := false
		for _, x := range loaded {
			if x.covers(one) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// MissingRules returns the lines of the recommended rules that the loaded
// rules (`auditctl -l` output) do not already record, leaving out watches
// on paths that do not exist (a watch on a missing path stops the rest of
// the rules loading). Key names are ignored, so rules a STIG baseline has
// already loaded under its own keys are not added twice.
func MissingRules(recommended, loaded string, exists func(string) bool) []string {
	var have []auditRule
	for _, l := range strings.Split(loaded, "\n") {
		if r, ok := parseAuditRule(l); ok {
			have = append(have, r)
		}
	}
	var out []string
	for _, l := range strings.Split(recommended, "\n") {
		r, ok := parseAuditRule(l)
		if !ok {
			continue
		}
		if r.watch != "" && exists != nil && !exists(r.watch) {
			continue
		}
		if !r.coveredBy(have) {
			out = append(out, r.raw)
		}
	}
	return out
}

// ruleTokens splits loaded rules into their words, for exact matching.
func ruleTokens(rules []string) [][]string {
	var out [][]string
	for _, r := range rules {
		out = append(out, strings.Fields(r))
	}
	return out
}

// watchesPath reports whether a rule watches exactly path (a -w rule, or a
// path= or dir= condition), ignoring a trailing slash.
func watchesPath(fields []string, path string) bool {
	path = normPath(path)
	for i, f := range fields {
		switch {
		case f == "-w" && i+1 < len(fields) && normPath(fields[i+1]) == path:
			return true
		case strings.HasPrefix(f, "path=") && normPath(strings.TrimPrefix(f, "path=")) == path:
			return true
		case strings.HasPrefix(f, "dir=") && normPath(strings.TrimPrefix(f, "dir=")) == path:
			return true
		}
	}
	return false
}

// ruleKey identifies what a rule records, for comparing rules written in
// different ways.
func ruleKey(r auditRule) string {
	var sc []string
	for s := range r.syscalls {
		sc = append(sc, s)
	}
	sort.Strings(sc)
	return strings.Join([]string{r.watch, r.perm, r.list, r.arch, strings.Join(sc, ","), strings.Join(r.filters, " ")}, "|")
}

// NotInRulesD counts the rules in /etc/audit/audit.rules that no file in
// /etc/audit/rules.d holds. augenrules rebuilds audit.rules from rules.d,
// so it would drop them: Ubuntu's `usg fix` writes audit.rules directly.
func NotInRulesD(auditRules string, rulesD []string) int {
	have := map[string]bool{}
	for _, f := range rulesD {
		for _, l := range strings.Split(f, "\n") {
			if r, ok := parseAuditRule(l); ok {
				have[ruleKey(r)] = true
			}
		}
	}
	n := 0
	for _, l := range strings.Split(auditRules, "\n") {
		if r, ok := parseAuditRule(l); ok && !have[ruleKey(r)] {
			n++
		}
	}
	return n
}
