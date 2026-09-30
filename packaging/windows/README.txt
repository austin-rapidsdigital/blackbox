BLACKBOX - audit log reports for air-gapped systems
===================================================

INSTALL
  Double-click Install.cmd and approve the administrator prompt.
  It asks two questions, sets up hourly collection, checks the audit
  settings, and produces the first report.

REPORTS
  C:\ProgramData\Blackbox\reports\index.html   (list of all reports)
  Each report is a single report.html file; open it in any browser.

SETTINGS
  C:\ProgramData\Blackbox\blackbox.conf

OTHER COMMANDS (from an administrator Command Prompt)
  blackbox.exe report      produce a report now
  blackbox.exe check       compare audit settings with the DISA STIG
  blackbox.exe verify DIR  confirm a report has not been altered

UNINSTALL
  Double-click Uninstall.cmd (reports are kept).

Documentation: https://github.com/casea1/blackbox
