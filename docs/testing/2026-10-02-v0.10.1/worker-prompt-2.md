You're working on Blackbox (github.com/casea1/blackbox). Your fixes for the first work list (`worker-prompt.md`, released as 0.10.2–0.10.4) were re-tested live on 4–5 Oct 2026: Windows Server 2025 collector + Ubuntu 26.04 sender, delivering over the SFTP (sshfs) route because the test VMs can't see each other. Results are in `docs/testing/2026-10-02-v0.10.1/findings.md`, section "v0.10.4 verification", with evidence and raw-record fixtures in `v0.10.4/`. If that folder isn't in your checkout, this prompt is enough to work from.

Same review lens: an ISSO doing the weekly review (AU-6) and an assessor checking that what the STIG makes you audit is actually reviewed. Same owner decisions (`docs/design.md` §13, `docs/redesign/SPEC.md`): no sign-off/review section, no classification banner, report only (never change audit settings), no third-party dependencies, plain-English sentences, ADM-Toolkit stays out of reports.

**Confirmed fixed in 0.10.4, don't regress:** A1, A3, A4/A12, A6, A7 (sources), A9, C5 (collector), L1, L3, L4, L5, N1, O1 (the `check`), S3, U1, U3, U6 (the spray detection), U7, U11, U12, A5/U9 on Linux, V1, V2, the upgrade path on both OSes, and the SCAP-results feature end to end (OpenSCAP scan → sender → collector → table, Systems badge, Overview CAT I, CSV, manifest).

Work in this order, one PR per group, each with tests (use the real records in `v0.10.4/*.log` as fixtures where given), gofmt, vet on Linux and Windows, docs in the same PR, and finding IDs in commit messages.

## 1. Accuracy: wrong statements in the report (do first)

- **U5 (regressed).** 3 wrong passwords for the existing user `bbuser` gave 8 rows, 5 saying "the user name does not exist". Two causes, both in `v0.10.4/u5-openssh10-audit-records.log` + `u5-openssh10-auth.log`:
  1. OpenSSH 10 leaves a PAM `USER_AUTH res=failed` and an sshd `USER_LOGIN op=login res=failed` per attempt (same `pid`, ~2 s apart). Merge them into one attempt per pid (keep "wrong password or key"); the guessing detection must count attempts, not records.
  2. For an unknown user, sshd's `USER_LOGIN acct="(invalid user)"` comes **before** that session's `USER_AUTH acct="admin"`. `triedName` only looks backwards, finds no same-pid record, and its address-only fallback (same addr, 3 s) takes bbuser's previous attempt from another session; `unknownNames` then rewrites bbuser's real failures. Match by pid in both directions (or resolve in a second pass), and drop the address-only fallback when the pids differ. The auth.log `Invalid user admin from 127.0.0.1` line carries the name and pid too.
- **O1 (not working).** The sudo-rs journal fallback is selected but never matches: `sudoRE` (`translate_syslog.go:244`) requires `TTY=`, and sudo-rs writes `claude :  PWD=/home/claude ; USER=root ; COMMAND=/usr/bin/grep -c . /dev/null` (no TTY field without a terminal; note the double space). Make TTY optional and add `v0.10.4/o1-sudo-rs-journal.log` as a fixture; expect "claude used sudo to run … as root/as bbuser" rows. A non-sudoer's refused sudo-rs is still logged nowhere: say so in `check`'s sudo-rs finding.
- **U8 (not working).** DAEMON_END is `op=terminate auid=0 uid=0 pid=1`: systemd sent the signal, so the actor is "root" and `stoppedBy()` is never consulted (it runs only when the actor is empty). When the record's pid is 1, attribute the stop with `stoppedBy()` ("stopped by claude (systemctl stop auditd)").
- **A15 + A5 on Windows: have Blackbox record its own setting changes.** Today the row is inferred from a command line:
  - On Linux a *refused* `config set retention_days 30` (answered "n") still reads High "claude changed Blackbox's retention_days setting".
  - On Windows `config set` leaves **no** row. `blackbox.exe`'s own writes are skipped on purpose, and the command line needs 4688 with command-line logging, which a fresh server doesn't have (Process Creation "No Auditing"; no SACL on `C:\ProgramData\Blackbox` either).

  Fix: when `config set` (or setup, upgrade or uninstall) actually writes a setting, Blackbox appends its own event: who (SUDO_USER/auid on Linux, the token user on Windows), which setting, old → new. It writes the event to its spool and to the OS log (Windows Application log, source "Blackbox"; syslog/journal ident `blackbox`), so a copy exists outside its own folder. Report it High for `exclude_*`/`retention_days`/`send_to`/`scap_results`, Medium otherwise. A command-line row with no matching self-record becomes "tried to change … (not applied)". On Windows, `check` should report whether `C:\ProgramData\Blackbox` has the SACL windows.md describes ("Blackbox's own folder not audited"), and Audit health should show it the way Linux shows "Blackbox's own files watched".
- **L9.** `reject()` (`receive.go:195`) ignores the `os.Rename` error and always logs "set aside in …\rejected". An unreadable file stays in the inbox, is retried every run, and status says "Inbox: OK; 1 batch waiting". Only claim "set aside" if the move worked; otherwise status and the report say "1 file in the inbox can't be read (access denied): <name>".
- **U13 (now frequent).** `tampers()` (`translate_audit.go` ~477) is still a substring match: `sh -c "rm -rf /tmp/rl9; ls /var/log/audit"` and any report command that names `--audit /var/log/audit/audit.log` are High "can stop or weaken auditing". Split the command line on `;`, `&&`, `||` and `|`, then test each part's program and its path arguments (and `>`/`>>` redirect targets).
- **U14.** `groupadd bbgrp2` still gives Medium "claude added bbgrp2 to a group (the log does not say which)" and `groupdel` gives "removed bbgrp2 from a group". ADD_GROUP/DEL_GROUP for creating or deleting a group are not membership changes.
- **R10.** The printed summary still ends with ISSO / Date / ISSM lines (`<div class="pt-lines">`), against design.md's "no signature or review section". Remove them.
- **U15.** "off for 0 minutes (23:57:19 to 23:57:20)" should read "less than a minute".

## 2. Noise that buries real findings

- **A13 (new, from the A7 firewall source).** A fresh Server 2025 gave 74 Low "A Windows Firewall rule was added by NT SERVICE\mpssvc: @{Microsoft.AAD.BrokerPlugin…}" (rules Windows registers for built-in app packages), 32 Medium 2052 "rule deleted" and 17 2099 "changed". A person enabling SMB-In is lost among them. Collapse changes made by `NT SERVICE\mpssvc` to `@{…}` package rules into one Info count per day, and keep changes made by people at their severity.
- **A14 (new, from the A3 rules).**
  - `groupadd` adds Medium "deleted or renamed /etc/group+, /etc/group, /etc/group" (shadow-utils writes `/etc/group+` and renames it over) and two Low owner/permission rows. Fold the temp-file rename into the account/group change row.
  - A `blackbox run` gives 9 Low "changed the permissions of /var/lib/blackbox/.state.json.tmp-…" rows (its own atomic writes). Leave out Blackbox's own writes under its data folder when the program is Blackbox; others' writes there stay High (A5).
- **W1 (worse).** A computer's pre-OOBE name (`WIN-R5L5B9EF403`) shows as a third system with 74 rows; the firewall events carry the old name, and the report folder is named `…_3-systems`. Systems should be only computers that collect (as the LAN import already does). Show events recorded under a former name on the current computer, with a detail "recorded under its former name …".
- **W2.** 41 Medium "First use of administrator rights" for `VIRTUAL USERS\sshd_<pid>`: OpenSSH for Windows runs each session as a new virtual account. Attribute it to the real user (the session's 4624 names `claude`) or treat `VIRTUAL USERS\sshd_*` as one service identity.
- **W3.** 88 Medium "PowerShell script … flagged as suspicious" from routine `Get-/Set-NetFirewallRule`. Join the parts of one ScriptBlockId (MessageNumber/MessageTotal) into one row, and recognise Microsoft's CDXML-generated module code (`$__cmdletization_*`).
- **W4.** 28 Medium "SYSTEM renamed account X to X" (4781 with the same old and new name, from OOBE) and "added claude to the group None" (4728 for the default primary group). Skip both.

## 3. Delivery resilience (the owner asked: do senders keep data while the collector is down, and resend it?)

Today: batches wait in the outbox (`/var/lib/blackbox/outbox`, `C:\ProgramData\Blackbox\outbox`) and go oldest first at the next run. 114 batches and 2 log archives queued over ~27 h were delivered in 47 s with 0 rejected; duplicates are skipped and gaps reported. Close the holes:

- **L8 (unchanged; most important).** On the SFTP route `blackbox.service` has `ReadWritePaths=… -/mnt/blackbox-inbox`. When sshfs is down, systemd can't build the namespace (`226/NAMESPACE … Input/output error`, or "Transport endpoint is not connected" with an automount), so **collection stops** for the whole outage, and the shutdown unit fails the same way. Principle: a delivery problem must never stop collection. Either:
  - deliver from a separate unit (`blackbox-send.service`) whose failure doesn't affect collection; or
  - have Blackbox own the sshfs mount the way it owns the SMB one (under `/var/lib/blackbox/collector`, e.g. `send_to = sftp://bbsend@COLLECTOR/C:/BlackboxInbox`) and check reachability inside the program.

  Also test a dead *established* CIFS hard mount on the SMB route for the same failure.
- **L7.** The documented sshfs fstab line doesn't recover from a mount that failed at boot. Nothing remounts a folder-type `send_to`, so the sender queues until someone mounts it by hand. Once L8 is fixed, recommend `x-systemd.automount,nofail` (it currently makes L8 worse), or remount before each run as the SMB route does.
- **L6.** "collector inbox not available" hides the cause. Include the mount unit's or connection's error (e.g. "No route to host", "Permission denied (publickey)") and the share name, in the log and in `status`.
- **L10 (new).** The outbox has no age or space warning. `status` says "Waiting to send: N batches" only. Add:
  - the age of the oldest waiting item, and a warning (status, tray, Linux `blackbox status` exit code) after 24 h;
  - a free-space check on the data folder.

  Never delete queued evidence to make room. Document "when the collector is unreachable" in lan.md: what is kept, where, for how long, and how to force a send (`blackbox send`).
- **L11 (new, proposal for the owner).** A batch is deleted from the outbox once copied, so if the collector loses inbox files before importing them (or its spool is restored from backup), it reports a gap the sender can't fill. Keep delivered batches for `keep_sent_days` (default 14) and add `blackbox send --resend 214-219`. The collector already accepts a batch that fills a gap (`inGap`/`fillGap`) and skips repeats. Write it up in design.md first if you think it needs approval.
- **N2.** Sharing the inbox doesn't check the firewall: Server 2025 ships "File and Printer Sharing (SMB-In)" disabled, and setup says "Other computers can now send". At least check it and say so in setup and in `status`. Offering to enable it, scoped to the senders, is the owner's call.
- **S11/S12/S13.** Setup has no "accounts allowed to deliver" field when sharing (S11). "Virtual machines on this PC send to it (VirtualBox)" is ticked by default with the admin pre-filled on a server without VirtualBox (S12). The share allows offline caching; use `/CACHE:None` (S13).
- **SC2.** The sender log says "sent 1 batch(es) and 0 log archive(s)" when SCAP results also went: count them.
- **N3 (docs).** Windows OpenSSH has no post-quantum key exchange; Ubuntu's OpenSSH 10 warns "store now, decrypt later". Note it in security.md for the SFTP route (SC-8/SC-13).

## 4. SCAP

- **SC1.** With OpenSCAP + SSG results, all 144 rows of `scap-open-rules.csv` have empty `vuln_id` and `stig_id`. SCC puts the STIG ID in `rule-result@version`; OpenSCAP doesn't, but the results file embeds the Benchmark. Its `<Rule>` has `<reference href="https://www.cyber.mil/stigs/downloads/…">UBTU-24-300028</reference>` plus the SRG ID. Look the rule up by `idref`, and show the STIG ID in the table and the CSV (the POA&M is keyed on it).

## 5. STIG-image compatibility (from reviewing a USG `disa_stig`-hardened Ubuntu 24.04 image with FIPS on)

- **I1.** `99-blackbox.rules` sorts before SSG's key-named files (`actions.rules`, `privileged.rules` …; `augenrules` uses `ls -v`), so overlapping events get Blackbox's key instead of the STIG's. That matters to `ausearch -k` and to other tools reading keys. Install as `zz-blackbox.rules`, and still read the old name on upgrade.
- **I2.** `--missing`'s advice to copy all of `audit.rules` to `rules.d/50-existing.rules` duplicates rules already in `rules.d` (auditctl then stops loading at the duplicate). Print only the rules missing from `rules.d` (`NotInRulesD` already has them), and reword the "USG writes audit.rules directly" caution: upstream SSG writes both files.
- **I3.** ClamAV check: don't advise enabling a masked `clamav-daemon` when a containerised scanner is used (recognise it, or at least don't give that fix). On a FIPS host, note the host engine's limits.
- **I4.** Changes made through `systemd-run` (configuration management) carry no auid and vanish, except sudoers and account files. Report changes to PAM, `/etc/security`, sshd, `/etc/audit` and systemd units made without a logged-in user at Low, or link them to the `sudo` that started the run.
- **I5.** In `--missing`, treat `/sbin`↔`/usr/sbin` and `/bin`↔`/usr/bin` as the same on merged-/usr systems, so duplicate `fdisk`/`modprobe` rules aren't proposed.
- **I6 (docs, lan.md SFTP).** Under FIPS, SMB from Linux fails, so SFTP is the route. Note:
  - use ECDSA or RSA keys (FIPS OpenSSH refuses ed25519);
  - pin the host key with `ssh`, because `ssh-keyscan` aborts under FIPS;
  - see L7/L8 for the mount options.

  Later: `sec=krb5` with a machine keytab for domain-joined senders.
- **I7 (minor).** The 24.04 STIG watches `/var/log/sudo.log`, so every sudo user gets an Info "appended to /var/log/sudo.log" row per report. Collapse it.

## 6. Reports and CLI

- **R9.** `blackbox report --from/--to/--days` are silently ignored with `--audit`, `--syslog`, `--xml`, `--evtx` (`ReportFromFiles(in, *out)` gets no range). Apply the range, or refuse the combination.

## 7. Release (owner action)

- **A10.** Signing is wired up but the release is still NotSigned and has no `SHA256SUMS.asc`: the signing secrets aren't set in the repo. The owner needs to add them (code-signing cert + key passphrase, and the minisign/GPG key); then confirm a release shows Authenticode "Valid" and a verifiable `SHA256SUMS.asc`. The SBOM is fine.

## Done means

Everything above is fixed with tests, or written up in docs for the owner (L11, N2's enable option, I4 if you judge it too noisy). Add a "Fixed in" column to the v0.10.4 tables in findings.md, bump the version, and list the IDs in the release notes. I'll re-test live: U5 and O1 on Ubuntu 26.04 (OpenSSH 10, sudo-rs), A5/A15 on both OSes, A13/W1–W4 on a fresh Server 2025, the L8 outage test on the SFTP route, and SC1 with the same OpenSCAP scan. Still needing a live check that this rig can't do: SMB delivery between two machines, a Windows sender, and 4826 from a real boot-configuration change.
