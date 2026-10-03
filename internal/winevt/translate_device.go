// USB and removable media: removable-storage access, Plug and Play,
// and the System, Partition, Kernel-PnP and DriverFrameworks logs.

package winevt

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

// removableAccess handles 4663/4656 events from the Removable Storage
// audit subcategory.
func (t *Translator) removableAccess(r *Raw) *event.Event {
	if r.Task != taskRemovableStorage {
		return t.fileAccess(r)
	}
	user := t.subject(r)
	obj := r.Get("ObjectName")
	if t.MapDevicePath != nil {
		obj = t.MapDevicePath(obj)
	}
	proc := r.Get("ProcessName")
	access := r.Get("AccessList")
	failed := r.AuditFailure()
	op := fileOperation(access)
	if op == "" && !failed {
		return nil // metadata-only access (attributes, permissions)
	}
	e := &event.Event{Category: event.CatRemovable, User: user, Target: obj, Process: proc}
	switch {
	case failed:
		e.Action, e.Severity, e.Outcome = "removable_access_denied", event.SevMedium, "failure"
		e.Summary = fmt.Sprintf("%s was blocked from accessing removable media: %s", user, obj)
	case op == "write":
		e.Action, e.Severity = "removable_write", event.SevMedium
		e.Summary = fmt.Sprintf("%s wrote to removable media: %s", user, obj)
	case op == "delete":
		e.Action, e.Severity = "removable_delete", event.SevMedium
		e.Summary = fmt.Sprintf("%s deleted from removable media: %s", user, obj)
	case op == "execute":
		e.Action, e.Severity = "removable_execute", event.SevMedium
		e.Summary = fmt.Sprintf("%s ran a program from removable media: %s", user, obj)
	default:
		e.Action, e.Severity = "removable_read", event.SevLow
		e.Summary = fmt.Sprintf("%s read from removable media: %s", user, obj)
	}
	if proc != "" {
		e.Summary += " (using " + filepath.Base(winPath(proc)) + ")"
	}
	e.Summary += "."
	e.DedupeKey = "rm|" + e.Action + "|" + strings.ToLower(user+"|"+obj)
	e.AddDetail("File", obj)
	e.AddDetail("Access", expandTokens(access))
	e.AddDetail("Program", proc)
	return e
}

// fileOperation classifies an AccessList into write, delete, execute,
// read, or "" (metadata only).
func fileOperation(access string) string {
	has := func(tok string) bool { return strings.Contains(access, tok) }
	switch {
	case has("%%4417") || has("%%4418") || has("%%4420") || has("%%4424"):
		return "write"
	case has("%%1537") || has("%%4422"):
		return "delete"
	case has("%%4421"):
		return "execute"
	case has("%%4416"):
		return "read"
	}
	return ""
}

// pnpDevice handles 6416 "A new external device was recognized". Only
// storage and portable devices are reported.
func (t *Translator) pnpDevice(r *Raw) *event.Event {
	id := r.Get("DeviceId")
	class := r.Get("ClassName")
	d := parseDeviceID(id)
	if !d.storage && !strings.EqualFold(class, "WPD") && !strings.EqualFold(class, "DiskDrive") && !strings.EqualFold(class, "CDROM") {
		return nil
	}
	desc := r.Get("DeviceDescription")
	name := strings.TrimSpace(strings.TrimSuffix(desc, " USB Device"))
	if name == "" {
		name = d.name()
	}
	e := &event.Event{Category: event.CatRemovable, Severity: event.SevMedium, Action: "usb_connected",
		User: t.subject(r), Target: name, DedupeKey: "usb|" + d.key(id), Priority: 1}
	e.Summary = fmt.Sprintf("Removable device connected: %s%s.", name, d.serialText())
	e.AddDetail("Device", desc)
	e.AddDetail("Vendor", d.vendor)
	e.AddDetail("Product", d.product)
	e.AddDetail("Serial number", d.serial)
	e.AddDetail("Device class", class)
	e.AddDetail("Device ID", id)
	return e
}

func (t *Translator) system(r *Raw) *event.Event {
	switch {
	case r.EventID == 104 && strings.Contains(r.Provider, "Eventlog"):
		u := joinAccount(r.Get("SubjectDomainName"), r.Get("SubjectUserName"), r.Computer)
		ch := r.Get("Channel")
		if ch == "" {
			ch = "An event"
		} else {
			ch = "The " + ch
		}
		e := &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "log_cleared", User: u,
			Target: r.Get("Channel"), Summary: fmt.Sprintf("%s log was cleared by %s.", ch, orUnknown(u))}
		e.AddDetail("Backup file", r.Get("BackupPath"))
		return e
	case r.EventID == 7045:
		acct := r.Get("AccountName")
		by := ""
		if r.UserSID != "" && !t.isServiceAccount(r.UserSID, "") {
			by = t.resolve(r.UserSID)
		}
		return t.serviceInstalled(r, r.Get("ServiceName"), r.Get("ImagePath"), acct, by)
	case r.EventID == 1074:
		user := qualifiedAccount(r.Get("param7"), r.Computer)
		kind := strings.ToLower(r.Get("param5"))
		if kind == "" {
			kind = "restart/shutdown"
		}
		proc := r.Get("param1")
		e := &event.Event{Category: event.CatIntegrity, Action: "shutdown_initiated", User: user, Process: proc,
			Summary: fmt.Sprintf("%s initiated a %s", orUnknown(user), kind)}
		if proc != "" {
			if i := strings.Index(proc, " ("); i > 0 {
				proc = proc[:i] // "C:\...\shutdown.exe (WS-07)"
			}
			e.Summary += " using " + filepath.Base(winPath(proc))
		}
		if reason := r.Get("param3"); reason != "" {
			e.Summary += " — " + reason
		}
		e.Summary += "."
		e.AddDetail("Reason", r.Get("param3"))
		e.AddDetail("Comment", r.Get("param6"))
		return e
	case r.EventID == 6005 && r.Provider == "EventLog":
		return &event.Event{Category: event.CatIntegrity, Action: "system_start", DedupeKey: "boot", Priority: 2,
			Summary: "The system started (event log service started)."}
	case r.EventID == 6006 && r.Provider == "EventLog":
		return &event.Event{Category: event.CatIntegrity, Action: "system_stop",
			Summary: "The system shut down cleanly (event log service stopped)."}
	case r.EventID == 6008 && r.Provider == "EventLog":
		e := &event.Event{Category: event.CatIntegrity, Severity: event.SevLow, Action: "unexpected_shutdown",
			Summary: "The previous shutdown was unexpected (power loss, crash or forced power-off)."}
		if tm, dt := r.Get("Data0"), r.Get("Data1"); tm != "" {
			e.Summary = fmt.Sprintf("The system shut down unexpectedly at %s %s (power loss, crash or forced power-off).", dt, tm)
		}
		return e
	}
	return nil
}

// partition handles Partition/Diagnostic 1006, logged whenever a disk
// arrives or leaves. It records vendor, model, serial and size and is on
// by default in Windows 10/11.
func (t *Translator) partition(r *Raw) *event.Event {
	if r.EventID != 1006 {
		return nil
	}
	if strings.EqualFold(r.Get("IsSystem"), "true") || strings.EqualFold(r.Get("IsBoot"), "true") {
		return nil
	}
	bt := r.Get("BusType")
	if !removableBus(bt) && !virtualBus(bt) {
		return nil
	}
	name := strings.TrimSpace(r.Get("Manufacturer") + " " + r.Get("Model"))
	// Prefer the USB serial from the parent device ID so the same stick
	// matches its Kernel-PnP/6416 events; fall back to the disk serial.
	d := parseDeviceID(r.Get("ParentId"))
	serial := d.serial
	if serial == "" {
		serial = strings.TrimSpace(r.Get("SerialNumber"))
	}
	if name == "" {
		name = d.name()
	}
	if name == "" {
		name = "unnamed device"
	}
	capBytes, _ := strconv.ParseUint(r.Get("Capacity"), 10, 64)
	e := &event.Event{Category: event.CatRemovable, Target: name}
	bus := busTypes[bt]
	key := strings.ToLower(serial)
	if key == "" {
		key = strings.ToLower(name)
	}
	if capBytes == 0 {
		e.Action, e.Severity = "usb_disconnected", event.SevInfo
		e.Summary = fmt.Sprintf("Removable storage disconnected: %s%s.", name, serialSuffix(serial))
		e.DedupeKey = "usboff|" + key
	} else {
		e.Action, e.Severity = "usb_connected", event.SevMedium
		e.DedupeKey, e.Priority = "usb|"+key, 3
		if virtualBus(bt) {
			e.Action = "virtual_disk_mounted"
			e.Summary = fmt.Sprintf("A virtual disk (ISO/VHD file) was mounted: %s, %s.", name, humanBytes(capBytes))
			e.DedupeKey = "vd|" + key
		} else {
			e.Summary = fmt.Sprintf("%s storage connected: %s%s, %s.", bus, name, serialSuffix(serial), humanBytes(capBytes))
		}
	}
	e.AddDetail("Connection", bus)
	e.AddDetail("Manufacturer", r.Get("Manufacturer"))
	e.AddDetail("Model", r.Get("Model"))
	e.AddDetail("Serial number", serial)
	if ds := strings.TrimSpace(r.Get("SerialNumber")); ds != "" && ds != serial {
		e.AddDetail("Disk serial number", ds)
	}
	if capBytes > 0 {
		e.AddDetail("Capacity", humanBytes(capBytes))
	}
	e.AddDetail("Device ID", r.Get("ParentId"))
	e.Fields = trimFields(r.Data, "Mbr", "Vbr0", "Vbr1", "Vbr2", "Vbr3", "PartitionTable", "UserData")
	return e
}

// kernelPnP handles Kernel-PnP/Configuration 400 (device configured),
// logged when a device is set up, including its first connection.
func (t *Translator) kernelPnP(r *Raw) *event.Event {
	if r.EventID != 400 {
		return nil
	}
	id := r.Get("DeviceInstanceId")
	d := parseDeviceID(id)
	if !d.storage {
		return nil
	}
	name := d.name()
	e := &event.Event{Category: event.CatRemovable, Severity: event.SevMedium, Action: "usb_connected", Target: name,
		DedupeKey: "usb|" + d.key(id), Priority: 2,
		Summary: fmt.Sprintf("Removable storage device configured (connected): %s%s.", name, d.serialText())}
	e.AddDetail("Vendor", d.vendor)
	e.AddDetail("Product", d.product)
	e.AddDetail("Serial number", d.serial)
	e.AddDetail("Driver", r.Get("DriverName"))
	e.AddDetail("Device ID", id)
	return e
}

// driverFrameworks handles DriverFrameworks-UserMode 2003/2100 (off by
// default; STIG-hardened systems often enable it).
func (t *Translator) driverFrameworks(r *Raw) *event.Event {
	if r.EventID != 2003 && r.EventID != 2100 && r.EventID != 2102 {
		return nil
	}
	var id string
	for _, v := range r.Data {
		if strings.Contains(strings.ToUpper(v), "USBSTOR") {
			id = v
			break
		}
	}
	if id == "" {
		return nil
	}
	d := parseDeviceID(id)
	name := d.name()
	if r.EventID == 2003 {
		return &event.Event{Category: event.CatRemovable, Severity: event.SevMedium, Action: "usb_connected", Target: name,
			DedupeKey: "usb|" + d.key(id), Priority: 0,
			Summary: fmt.Sprintf("USB storage connected: %s%s.", name, d.serialText())}
	}
	return &event.Event{Category: event.CatRemovable, Action: "usb_disconnected", Target: name,
		DedupeKey: "usboff|" + d.key(id),
		Summary:   fmt.Sprintf("USB storage disconnected: %s%s.", name, d.serialText())}
}

func serialSuffix(s string) string {
	if s == "" {
		return ""
	}
	return " (serial " + s + ")"
}

func humanBytes(b uint64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d bytes", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// device is what can be read from a Windows device instance ID such as
// USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530001231109115405&0
type device struct {
	vendor, product, serial string
	storage                 bool
}

func parseDeviceID(id string) device {
	var d device
	up := strings.ToUpper(id)
	// DriverFrameworks uses '#' where the registry uses '\'.
	norm := strings.ReplaceAll(id, "#", `\`)
	switch {
	case strings.Contains(up, "USBSTOR"):
		d.storage = true
	case strings.HasPrefix(up, `SWD\WPDBUSENUM`) || strings.HasPrefix(up, `WPD`):
		d.storage = true
	case strings.HasPrefix(up, `SCSI\DISK`) && strings.Contains(up, "USB"):
		d.storage = true
	}
	parts := strings.Split(norm, `\`)
	for _, p := range parts {
		for _, f := range strings.Split(p, "&") {
			lf := strings.ToLower(f)
			switch {
			case strings.HasPrefix(lf, "ven_") && d.vendor == "":
				d.vendor = strings.ReplaceAll(strings.Trim(f[4:], "_ "), "_", " ")
			case strings.HasPrefix(lf, "prod_") && d.product == "":
				d.product = strings.ReplaceAll(strings.Trim(f[5:], "_ "), "_", " ")
			}
		}
	}
	// The last part of ENUMERATOR\HARDWARE-ID\INSTANCE is the device serial
	// when the device reports one. Windows-generated instance IDs contain
	// '&' (e.g. 6&2c0f7b2&0&1), so those are ignored.
	if len(parts) >= 3 {
		s := strings.TrimSpace(parts[len(parts)-1])
		if j := strings.LastIndex(s, "&"); j > 0 && len(s)-j <= 3 {
			s = s[:j] // strip the "&0" instance suffix
		}
		if s != "" && !strings.Contains(s, "&") && !strings.HasPrefix(s, "{") {
			d.serial = s
		}
	}
	return d
}

func (d device) name() string {
	return strings.TrimSpace(d.vendor + " " + d.product)
}

func (d device) serialText() string { return serialSuffix(d.serial) }

func (d device) key(fallback string) string {
	if d.serial != "" {
		return strings.ToLower(d.serial)
	}
	if n := d.name(); n != "" {
		return strings.ToLower(n)
	}
	return strings.ToLower(fallback)
}
