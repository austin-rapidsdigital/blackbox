//go:build windows

package winevt

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Thin wrapper over the Windows Event Log API (wevtapi.dll). Events are
// rendered as XML and handed to the same parser used for exported files.

var (
	modwevtapi    = syscall.NewLazyDLL("wevtapi.dll")
	procEvtQuery  = modwevtapi.NewProc("EvtQuery")
	procEvtNext   = modwevtapi.NewProc("EvtNext")
	procEvtRender = modwevtapi.NewProc("EvtRender")
	procEvtClose  = modwevtapi.NewProc("EvtClose")

	modkernel32         = syscall.NewLazyDLL("kernel32.dll")
	procQueryDosDeviceW = modkernel32.NewProc("QueryDosDeviceW")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryFilePath         = 0x2
	evtQueryForwardDirection = 0x100
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1

	errNoMoreItems        = syscall.Errno(259)
	errInsufficientBuffer = syscall.Errno(122)
	errEvtChannelNotFound = syscall.Errno(15007)
	errEvtInvalidQuery    = syscall.Errno(15001)
	errAccessDenied       = syscall.Errno(5)
	infinite              = 0xFFFFFFFF
	batchSize             = 128
)

// Supported reports whether live collection works on this OS.
const Supported = true

// ErrChannelNotFound means the log does not exist or is disabled.
var ErrChannelNotFound = errors.New("log not found or not enabled")

type evtHandle uintptr

func evtClose(h evtHandle) {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}

func evtQuery(path, query string, flags uint32) (evtHandle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	q, err := syscall.UTF16PtrFromString(query)
	if err != nil {
		return 0, err
	}
	r, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(q)), uintptr(flags))
	if r == 0 {
		if e == errEvtChannelNotFound {
			return 0, ErrChannelNotFound
		}
		if e == errAccessDenied {
			return 0, fmt.Errorf("access denied reading %s (run as Administrator or SYSTEM)", path)
		}
		return 0, fmt.Errorf("EvtQuery %s: %w", path, e)
	}
	return evtHandle(r), nil
}

// renderXML renders one event handle as XML text.
func renderXML(h evtHandle, buf *[]uint16) (string, error) {
	var used, props uint32
	for {
		var ptr uintptr
		if len(*buf) > 0 {
			ptr = uintptr(unsafe.Pointer(&(*buf)[0]))
		}
		r, _, e := procEvtRender.Call(0, uintptr(h), evtRenderEventXML,
			uintptr(len(*buf)*2), ptr, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return syscall.UTF16ToString((*buf)[:used/2]), nil
		}
		if e != errInsufficientBuffer {
			return "", fmt.Errorf("EvtRender: %w", e)
		}
		*buf = make([]uint16, used/2+1)
	}
}

// readQuery runs a query and calls fn for each event, stopping after max
// events when max > 0.
func readQuery(path, query string, flags uint32, max int, fn func(*Raw) error) error {
	rs, err := evtQuery(path, query, flags)
	if err != nil {
		return err
	}
	defer evtClose(rs)
	handles := make([]evtHandle, batchSize)
	buf := make([]uint16, 16*1024)
	seen := 0
	for {
		var returned uint32
		r, _, e := procEvtNext.Call(uintptr(rs), uintptr(len(handles)),
			uintptr(unsafe.Pointer(&handles[0])), infinite, 0, uintptr(unsafe.Pointer(&returned)))
		if r == 0 {
			if e == errNoMoreItems {
				return nil
			}
			if e == errEvtInvalidQuery {
				return fmt.Errorf("invalid query for %s", path)
			}
			return fmt.Errorf("EvtNext %s: %w", path, e)
		}
		var ferr error
		for i := 0; i < int(returned); i++ {
			if ferr == nil {
				var x string
				x, ferr = renderXML(handles[i], &buf)
				if ferr == nil {
					var raw *Raw
					raw, ferr = ParseEvent([]byte(x))
					if ferr == nil {
						ferr = fn(raw)
					}
				}
			}
			evtClose(handles[i])
		}
		if ferr != nil {
			return ferr
		}
		seen += int(returned)
		if max > 0 && seen >= max {
			return nil
		}
	}
}

// ReadChannel calls fn for every event in a live log with a record number
// greater than after, oldest first.
func ReadChannel(channel string, after uint64, fn func(*Raw) error) error {
	q := "*"
	if after > 0 {
		q = fmt.Sprintf("*[System[EventRecordID>%d]]", after)
	}
	return readQuery(channel, q, evtQueryChannelPath|evtQueryForwardDirection, 0, fn)
}

// Edges returns the oldest and newest events currently in a log (nil if
// the log is empty).
func Edges(channel string) (oldest, newest *Raw, err error) {
	grab := func(dir uint32) (*Raw, error) {
		var got *Raw
		err := readQuery(channel, "*", evtQueryChannelPath|dir, 1, func(r *Raw) error {
			if got == nil {
				got = r
			}
			return nil
		})
		return got, err
	}
	if oldest, err = grab(evtQueryForwardDirection); err != nil {
		return nil, nil, err
	}
	if newest, err = grab(evtQueryReverseDirection); err != nil {
		return nil, nil, err
	}
	return oldest, newest, nil
}

// ReadFile calls fn for every event in an exported .evtx file.
func ReadFile(path string, fn func(*Raw) error) error {
	return readQuery(path, "*", evtQueryFilePath|evtQueryForwardDirection, 0, fn)
}

// LookupSID resolves a SID to DOMAIN\name using the local system.
func LookupSID(sid string) string {
	s, err := syscall.StringToSid(sid)
	if err != nil {
		return ""
	}
	acct, dom, _, err := s.LookupAccount("")
	if err != nil || acct == "" {
		return ""
	}
	if dom == "" {
		return acct
	}
	return dom + `\` + acct
}

// DevicePathMapper returns a function that rewrites
// \Device\HarddiskVolumeN\… to a drive-letter path.
func DevicePathMapper() func(string) string {
	m := map[string]string{}
	buf := make([]uint16, 1024)
	for c := 'A'; c <= 'Z'; c++ {
		drive := string(c) + ":"
		p, _ := syscall.UTF16PtrFromString(drive)
		n, _, _ := procQueryDosDeviceW.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n == 0 {
			continue
		}
		target := syscall.UTF16ToString(buf[:n])
		if target != "" {
			m[strings.ToLower(target)] = drive
		}
	}
	return func(path string) string {
		lp := strings.ToLower(path)
		for dev, drive := range m {
			if strings.HasPrefix(lp, dev+`\`) {
				return drive + path[len(dev):]
			}
		}
		return path
	}
}
