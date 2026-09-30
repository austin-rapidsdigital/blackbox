package linuxlog

// RecordTypeNames explains common auditd record types for the log volume
// table.
var RecordTypeNames = map[string]string{
	"SYSCALL": "System call (kernel audit rule matched)", "EXECVE": "Program arguments", "PATH": "File involved",
	"CWD": "Working directory", "PROCTITLE": "Command line", "EOE": "End of event",
	"USER_AUTH": "Authentication attempt", "USER_ACCT": "Account check", "USER_LOGIN": "Logon", "USER_LOGOUT": "Logoff",
	"USER_START": "Session opened", "USER_END": "Session closed", "USER_CMD": "sudo command",
	"CRED_ACQ": "Credentials acquired", "CRED_DISP": "Credentials released", "CRED_REFR": "Credentials refreshed",
	"USER_CHAUTHTOK": "Password change", "ADD_USER": "User account created", "DEL_USER": "User account deleted",
	"ADD_GROUP": "Group created", "DEL_GROUP": "Group deleted", "USER_MGMT": "User account changed",
	"CONFIG_CHANGE": "Audit configuration changed", "DAEMON_START": "Audit service started", "DAEMON_END": "Audit service stopped",
	"SERVICE_START": "Service started", "SERVICE_STOP": "Service stopped", "SYSTEM_BOOT": "System boot",
	"SYSTEM_SHUTDOWN": "System shutdown", "AVC": "SELinux/AppArmor decision", "USER_AVC": "SELinux decision (user space)",
	"ANOM_ABEND": "Program crashed", "ANOM_PROMISCUOUS": "Network capture mode changed", "BPF": "BPF program loaded",
	"NETFILTER_CFG": "Firewall rules changed", "KERN_MODULE": "Kernel module", "SOCKADDR": "Network address",
	"TTY": "Keystrokes (TTY auditing)", "USER_TTY": "Keystrokes (TTY auditing)",
	"LOGIN": "Login ID set", "USER_ROLE_CHANGE": "SELinux role change", "MAC_STATUS": "SELinux mode changed",
	"ANOM_LOGIN_FAILURES": "Too many failed logons", "RESP_ACCT_LOCK": "Account locked",
	"kernel": "Kernel messages", "sshd": "SSH server", "sudo": "sudo", "CRON": "Scheduled jobs (cron)",
	"systemd": "Service manager", "NetworkManager": "Network manager", "udisksd": "Disk mounting service",
}
