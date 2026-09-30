BLACKBOX - audit log reports for air-gapped systems
===================================================

INSTALL
  sudo ./install.sh --site "Lab 3" --report-every weekly
  Sets up an hourly systemd timer, checks the audit configuration, and
  produces the first report.

  auditd is required by the STIG and gives the most complete reports:
    sudo apt install auditd          (Ubuntu)   or   sudo dnf install audit   (Alma)
    sudo blackbox check --audit-rules | sudo tee /etc/audit/rules.d/99-blackbox.rules
    sudo augenrules --load

REPORTS
  /var/lib/blackbox/reports/index.html   (list of all reports)

SETTINGS
  /etc/blackbox/blackbox.conf

OTHER COMMANDS
  sudo blackbox report       produce a report now
  sudo blackbox check        compare audit settings with the DISA STIG
  blackbox verify DIR        confirm a report has not been altered

UNINSTALL
  sudo ./uninstall.sh (reports are kept)

Documentation: https://github.com/casea1/blackbox
