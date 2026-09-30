BLACKBOX - audit log reports for air-gapped systems
===================================================

INSTALL
  sudo ./install.sh
  Answer the questions (press Enter to accept each default). Setup
  schedules hourly collection, checks the audit configuration, and
  produces the first report.

  auditd is required by the STIG and gives the most complete reports:
    sudo apt install auditd          (Ubuntu)   or   sudo dnf install audit   (Alma)
    sudo blackbox check --audit-rules | sudo tee /etc/audit/rules.d/99-blackbox.rules
    sudo augenrules --load

SEVERAL COMPUTERS (a VM on a Windows PC, or a LAN)
  The first question asks how this computer's events are reviewed. Choose
  "Send to a collector" and give the collector's inbox: a VirtualBox shared
  folder (for example /media/sf_BlackboxInbox) or a Windows share (for
  example //COLLECTOR/BlackboxInbox; needs cifs-utils). Set up the
  collector first. See docs/lan.md in the documentation.

CHANGE SETTINGS LATER (for example, the report folder)
  Run sudo ./install.sh again: it shows the current settings as the
  defaults, so change only what you need.

REPORTS
  Default folder: /var/lib/blackbox/reports  (open index.html)

CHECK IT IS WORKING
  sudo blackbox status

UNINSTALL
  sudo ./uninstall.sh   (reports and settings are kept)

No other software is needed on the system.
Documentation: https://github.com/casea1/blackbox
