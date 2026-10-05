package check

import (
	"strings"
)

// OwnFolder is Blackbox's data folder on Windows.
const OwnFolder = `C:\ProgramData\Blackbox`

// OwnFolderAuditQuery lists the auditing entries (SACL) on Blackbox's
// folder, one "identity|rights|flags" line each. Reading a SACL needs an
// administrator or SYSTEM.
const OwnFolderAuditQuery = `$ErrorActionPreference='Stop'; foreach ($r in (Get-Acl -Audit '` + OwnFolder + `').Audit) { "$($r.IdentityReference)|$($r.FileSystemRights)|$($r.AuditFlags)" }`

// OwnFolderAuditFix is the PowerShell in windows.md that adds the entry.
const OwnFolderAuditFix = `As an administrator, in PowerShell: $acl = Get-Acl ` + OwnFolder + ` -Audit; ` +
	`$acl.AddAuditRule((New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "Write,Delete,ChangePermissions,TakeOwnership", "ContainerInherit,ObjectInherit", "None", "Success,Failure"))); ` +
	`Set-Acl ` + OwnFolder + ` $acl (Blackbox never changes audit settings itself; see windows.md)`

// EvaluateOwnFolderAudit reports whether changes to Blackbox's own folder
// are audited (A5 on Windows): an auditing entry that records successful
// writes or deletes. Without one, File System auditing records nothing
// there, and an edit to Blackbox's settings or data is not reported. Not
// a STIG rule, so a missing entry is a warning.
func EvaluateOwnFolderAudit(out string, err error) Result {
	r := Result{Area: "Object auditing", Item: "Blackbox's own folder audited (" + OwnFolder + ")",
		Want: "Recommended: writes and deletes audited", Affects: "Audit & System Integrity (changes to Blackbox's settings and data)"}
	if err != nil {
		r.Status, r.Have = Error, "could not read its auditing entries: "+strings.TrimSpace(err.Error())
		return r
	}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(l), "|")
		if len(f) < 3 {
			continue
		}
		rights, flags := strings.ToLower(f[1]), strings.ToLower(f[2])
		if strings.Contains(flags, "success") && (strings.Contains(rights, "write") || strings.Contains(rights, "delete") ||
			strings.Contains(rights, "modify") || strings.Contains(rights, "fullcontrol")) {
			r.Status, r.Have = Pass, "Audited ("+strings.TrimSpace(f[0])+": "+f[1]+")"
			return r
		}
	}
	r.Status, r.Have, r.Fix = Warn, "Not audited", OwnFolderAuditFix
	return r
}
