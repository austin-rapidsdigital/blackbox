# Blackbox 0.10.1 to 0.10.4: test results, 2–5 Oct 2026

Ubuntu 26.04 sender and Windows Server 2025 collector tested live (the Windows 11 VM never got past OOBE under nested KVM). Delivery went over SFTP (sshfs) because the test VMs are isolated from each other; the SMB route between machines is still untested. 0.10.4 (the worker's fixes for the first work list) was verified on 5 Oct, including SCAP results from a real OpenSCAP scan: see the "v0.10.4 verification" section of findings.md.

- [findings.md](findings.md): every finding by ID: 0.10.0 fixes re-checked, new findings, the Linux sender run, and an ISSO/ISSM review of audit coverage (AU-2/AU-6/AU-12) with Splunk-style roadmap items.
- [worker-prompt.md](worker-prompt.md): the first work list (done in 0.10.2), including the proposal to read SCAP (SCC/OpenSCAP) results into the report.
- [worker-prompt-2.md](worker-prompt-2.md): the second work list: what 0.10.4 didn't fix, what it introduced, the collector and delivery findings, SCAP, and STIG-image compatibility.
- [worker-prompt-3.md](worker-prompt-3.md): the third work list, from the 0.11.0 re-test and the Windows 11 standalone tests (clock changes, noise on a fresh Windows 11, SC3). Its [addendum](worker-prompt-3-addendum.md) added L12, U8b, U4b and A14b.
- [worker-prompt-4.md](worker-prompt-4.md): the fourth work list, from the 0.12.1 re-test: original-log archives (AR1-AR4), role changes (L13, L14, W1b) and smaller items.
- [worker-prompt-5.md](worker-prompt-5.md): UI/UX review of 0.15.0: trends counted per report instead of per week (UI1), a silent computer shown Healthy (UI2), hidden Audit health columns (UI3), upgrade read as covering of tracks (UI4), and smaller layout and wording items.
- [worker-prompt-6.md](worker-prompt-6.md): from the 0.16.1 re-test: false High rows from the per-collection exports (AR2b), the tray needing two clicks (TRAY1, owner report), a gap that never clears (L13b), and small items.
- [worker-prompt-7.md](worker-prompt-7.md): from the 0.17.0 re-test: a stale run lock that silently stops collection (LOCK1), the slow tray menu (TRAY2), and a docs note on old gaps (L13c).
- [worker-prompt-8.md](worker-prompt-8.md): from the 0.19.0 deep test: archiving stopped by one missing piece (AR5), "Security log cleared" for any log (LC1), a clear counted as rollover (LC2), the report ledger missing deleted logs (LEDGER1), STIG IDs on shared gap rows (STIG1), duplicated rows and data across the report (UX1–UX9), and smaller items.
- [worker-prompt-9.md](worker-prompt-9.md): from the 0.20.0 re-test: scheduled reports silently missing original logs when two runs fall in one minute (AR7), a clear still called an overwrite (LC2b), ledger gaps after upgrade (LEDGER1b, LEDGER3), doubled SSH logon rows and log-clear detections (UX1b, DUP2), labelled must fix or backlog.
- [test-plan.md](test-plan.md): what was planned, including the collector tests still to run.
- [test-activity.log](test-activity.log): every test action, timestamped (UTC).
- [scripts/](scripts/): the scripts typed into the VMs (test passwords come from environment variables and aren't stored).
- [shots/](shots/): screenshots. One test password in `ubu-09` is blacked out.
- [v0.19.0/](v0.19.0/): 0.19.0 deep-test screenshots (report overview, Audit health gaps table, a cleared-log report, All reports, Original logs, phone width, the status icon), and ux/ with every page of a collector report for the UI/UX review.
- [v0.20.0/](v0.20.0/): 0.20.0 re-test screenshots: a scheduled report with no original logs (AR7), a manual report's Overview, Original logs, Privileged activity and Search, Audit health with per-OS STIG IDs, and phone width.
- [v0.10.4/](v0.10.4/): 0.10.4 evidence: the Ubuntu activity rows and report summary, the Windows upgrade screens, the SCAP results summary and CSV, and raw records for U5 (OpenSSH 10) and O1 (sudo-rs) to use as test fixtures.
