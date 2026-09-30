// Package linuxlog reads Linux audit and system logs (auditd, syslog-style
// files and the systemd journal) and translates them into plain-English
// normalized events.
package linuxlog

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Record is one line of an auditd log.
type Record struct {
	Type   string
	Time   time.Time
	Serial uint64
	Node   string            // host name when auditd's name_format is set
	Fields map[string]string // decoded values; enriched names use UPPERCASE keys
}

// Get returns a field, treating auditd's placeholders as empty.
func (r *Record) Get(k string) string {
	switch v := r.Fields[k]; v {
	case "?", "(null)", "(none)", "-1", "4294967295", "unset":
		return ""
	default:
		return v
	}
}

// Event is every record auditd wrote for one audit event (same serial).
type Event struct {
	Time    time.Time
	Serial  uint64
	Node    string
	Records []*Record
}

// First returns the first record of a type, or nil.
func (e *Event) First(typ string) *Record {
	for _, r := range e.Records {
		if r.Type == typ {
			return r
		}
	}
	return nil
}

// All returns every record of a type.
func (e *Event) All(typ string) []*Record {
	var out []*Record
	for _, r := range e.Records {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

// Main is the record that describes the event: the SYSCALL record for
// kernel events, otherwise the first record.
func (e *Event) Main() *Record {
	if r := e.First("SYSCALL"); r != nil {
		return r
	}
	return e.Records[0]
}

var headerRE = regexp.MustCompile(`^(?:node=(\S+) )?type=(\S+) msg=audit\((\d+)\.(\d+):(\d+)\):\s?`)

// ErrNotAudit means a line is not an auditd record.
var ErrNotAudit = errors.New("not an auditd record")

// ParseRecord parses one auditd log line.
func ParseRecord(line string) (*Record, error) {
	m := headerRE.FindStringSubmatch(line)
	if m == nil {
		return nil, ErrNotAudit
	}
	sec, _ := strconv.ParseInt(m[3], 10, 64)
	ms, _ := strconv.ParseInt(m[4], 10, 64)
	serial, _ := strconv.ParseUint(m[5], 10, 64)
	r := &Record{Type: m[2], Node: m[1], Serial: serial,
		Time: time.Unix(sec, ms*int64(time.Millisecond)), Fields: map[string]string{}}
	body := line[len(m[0]):]
	// Enriched logs (log_format = ENRICHED) append resolved names after a
	// 0x1d separator, e.g. AUID="jsmith" UID="root".
	enriched := ""
	if i := strings.IndexByte(body, 0x1d); i >= 0 {
		body, enriched = body[:i], body[i+1:]
	}
	parseFields(body, r.Fields, r.Type)
	if r.Type == "AVC" || r.Type == "USER_AVC" {
		r.Fields["_raw"] = body // "avc:  denied  { read } for …" is not key=value
	}
	if enriched != "" {
		parseFields(enriched, r.Fields, r.Type)
	}
	return r, nil
}

// parseFields reads key=value pairs. Values may be "quoted", 'quoted'
// (user-space records nest their own fields in msg='…') or bare, and bare
// values of string fields are hex-encoded by auditd when they contain
// spaces or special characters.
func parseFields(s string, out map[string]string, typ string) {
	for i := 0; i < len(s); {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			return
		}
		key := s[i : i+eq]
		if strings.ContainsAny(key, " ") {
			// Not a key (e.g. "avc:  denied  { read } for  pid=…"): skip a word.
			sp := strings.IndexByte(s[i:], ' ')
			if sp < 0 {
				return
			}
			i += sp
			continue
		}
		i += eq + 1
		var val string
		quoted := false
		switch {
		case i < len(s) && s[i] == '"':
			end := strings.IndexByte(s[i+1:], '"')
			if end < 0 {
				val, i = s[i+1:], len(s)
			} else {
				val, i = s[i+1:i+1+end], i+end+2
			}
			quoted = true
		case i < len(s) && s[i] == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				end = len(s) - i - 1
			}
			inner := s[i+1 : i+1+end]
			i += end + 2
			if key == "msg" {
				parseFields(inner, out, typ)
				continue
			}
			val, quoted = inner, true
		default:
			end := strings.IndexByte(s[i:], ' ')
			if end < 0 {
				end = len(s) - i
			}
			val = s[i : i+end]
			i += end
		}
		if !quoted && hexField(key, typ) {
			if d, ok := decodeHex(val); ok {
				val = d
			}
		}
		out[key] = val
	}
}

var hexArg = regexp.MustCompile(`^a\d+$`)

// hexField lists fields auditd may hex-encode. Numeric fields (id, old,
// new…) and SYSCALL register arguments are never decoded.
func hexField(k, typ string) bool {
	switch k {
	case "proctitle", "cmd", "acct", "comm", "exe", "name", "cwd", "data", "path", "grp", "key":
		return true
	}
	return typ == "EXECVE" && hexArg.MatchString(k)
}

func decodeHex(v string) (string, bool) {
	if len(v) < 2 || len(v)%2 != 0 {
		return "", false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return "", false // auditd writes uppercase hex
		}
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return "", false
	}
	// Command lines are NUL-separated arguments.
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " ")), true
}

// multiRecord lists record types that belong to a kernel (SYSCALL) event,
// which auditd ends with an EOE record. All other types stand alone.
var multiRecord = map[string]bool{
	"SYSCALL": true, "EXECVE": true, "PATH": true, "CWD": true, "PROCTITLE": true,
	"SOCKADDR": true, "BPRM_FCAPS": true, "CAPSET": true, "MMAP": true, "FD_PAIR": true,
	"OBJ_PID": true, "NETFILTER_CFG": true, "KERN_MODULE": true, "EOE": true,
	"TIME_INJOFFSET": true, "TIME_ADJNTPVAL": true, "AVC": true, "SELINUX_ERR": true,
	"URINGOP": true, "OPENAT2": true, "IPC": true, "MQ_OPEN": true,
}

// Assembler groups records into events.
type Assembler struct {
	pending map[string]*Event
	order   []string
	emit    func(*Event) error
}

// NewAssembler returns an Assembler that calls emit for each complete event.
func NewAssembler(emit func(*Event) error) *Assembler {
	return &Assembler{pending: map[string]*Event{}, emit: emit}
}

func eventKey(r *Record) string { return r.Node + "|" + strconv.FormatUint(r.Serial, 10) }

// Add feeds one record.
func (a *Assembler) Add(r *Record) error {
	k := eventKey(r)
	ev := a.pending[k]
	if ev == nil {
		ev = &Event{Time: r.Time, Serial: r.Serial, Node: r.Node}
		a.pending[k] = ev
		a.order = append(a.order, k)
	}
	if r.Type == "EOE" {
		return a.finish(k)
	}
	ev.Records = append(ev.Records, r)
	if !multiRecord[r.Type] {
		return a.finish(k)
	}
	// Bound memory if EOE records are missing (older kernels, damaged logs).
	if len(a.order) > 512 {
		return a.finish(a.order[0])
	}
	return nil
}

func (a *Assembler) finish(k string) error {
	ev := a.pending[k]
	delete(a.pending, k)
	for i, o := range a.order {
		if o == k {
			a.order = append(a.order[:i], a.order[i+1:]...)
			break
		}
	}
	if ev == nil || len(ev.Records) == 0 {
		return nil
	}
	return a.emit(ev)
}

// Flush emits every event still waiting for its EOE record.
func (a *Assembler) Flush() error {
	for len(a.order) > 0 {
		if err := a.finish(a.order[0]); err != nil {
			return err
		}
	}
	return nil
}

// ParseAuditStream reads an auditd log and calls fn for each event. Lines
// that are not audit records are counted and skipped.
func ParseAuditStream(r io.Reader, fn func(*Event) error) (skipped int, err error) {
	asm := NewAssembler(fn)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		rec, perr := ParseRecord(sc.Text())
		if perr != nil {
			skipped++
			continue
		}
		if err := asm.Add(rec); err != nil {
			return skipped, err
		}
	}
	if err := sc.Err(); err != nil {
		return skipped, fmt.Errorf("read audit log: %w", err)
	}
	return skipped, asm.Flush()
}
