BLACKBOX - audit log reports for air-gapped systems
===================================================

INSTALL
  1. Extract this zip to a folder.
  2. Double-click Install.cmd and approve the administrator prompt.
  3. Answer the questions (press Enter to accept each default).
  Setup schedules hourly collection, checks the audit settings, and
  produces the first report.

SEVERAL COMPUTERS (a Linux VM on this PC, or a LAN)
  The first question asks how this computer's events are reviewed.
  - On the PC that should produce the reports, choose "This is the
    collector". Setup creates an inbox folder (C:\BlackboxInbox) and can
    share it with VirtualBox VMs on this PC and with the network.
  - On each other computer, including Linux VMs, choose "Send to a
    collector".
  Set up the collector first. See docs/lan.md in the documentation.

CHANGE SETTINGS LATER (for example, the report folder)
  Double-click Install.cmd again: it shows the current settings as the
  defaults, so change only what you need.

REPORTS
  Default folder: C:\ProgramData\Blackbox\reports  (open index.html)

CHECK IT IS WORKING
  Open Command Prompt as administrator and run:
    "C:\Program Files\Blackbox\blackbox.exe" status

UNINSTALL
  Settings > Apps > Blackbox > Uninstall, or double-click Uninstall.cmd.
  Reports and settings are kept.

No other software is needed on the system.
Documentation: https://github.com/casea1/blackbox
