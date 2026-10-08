You're working on Blackbox (github.com/casea1/blackbox). 0.24.0 was tested before production on 8 Oct 2026. The details are in findings.md, section "0.24.0 pre-production test", with screenshots in `v0.24.0/`. **Verdict: go.** This prompt is the follow-up for the next release. None of it blocks deployment.

**Confirmed live, don't regress:**
- the upgrade order (senders first) and emptying the 0.23 folders;
- the drop-only inbox ACL;
- signing, pinning and the "New sender" line;
- forgeries refused;
- key change → held → `senders rekey` (event 102) → imported;
- a Windows sender over SMB;
- the scheduled report's `verify`, `sha256sum -c` and README;
- the redesign on real data, with no console errors, no overflow at 1440 or 390 px, and the old links redirected.

## Must fix

- **SEC1e: the false gap after the collector upgrade.**
  - **What happened:** a batch waiting in a 0.23 folder at the upgrade is imported. The next delivery then lists it as missing, and `send --resend` imports it again (seen with 472).
  - **Fix:** carry the folder-time import record over to the sender-ID record before `MigrateSenderFolders` clears `InboxFolders`.
  - **Test:** a batch waiting in a 0.23 folder at the upgrade, followed by the next batch, gives no gap, and a resend says "already imported".
- **OS1: Linux OS label.** `osLabel` (report/overview.go:55) shows the settings check's baseline name, which on Linux is now "Blackbox's advice". Show the inventory OS ("Ubuntu 26.04.1 LTS") on Systems, Overview and each system's page.
- **PPL1: "Domain account".** On a network with no domain, People says "Domain account win11-test\claude" for three local accounts. Call an account a domain account only when its domain isn't one of the report's computer names. Otherwise say "Local account on N systems".
- **DET1: refused deletes.** A delete the OS refused (audit `success=no`, or a non-zero exit) is reported as "deleted Blackbox's files … 3 times" in a High detection. Report it as "tried to delete … (refused)", Medium, and don't count it as a removal. Test it with a refused unlink audit record.

## Backlog

- **SEC1f:**
  - Set aside non-delivery files in the inbox after 10 minutes.
  - Pin the key for batches emptied from 0.23 folders.
  - Say "already imported" for a replayed unsigned copy of an imported batch.
- **UI22:**
  - A first-time sender's Reporting cell is grey ("no data") although it delivered.
  - Overview's summary prints two full key fingerprints; shorten them.

## Done means

- The must-fix items are fixed, with tests.
- The new findings rows get "Fixed in".
- The version is bumped.
