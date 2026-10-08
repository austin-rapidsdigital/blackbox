You're working on Blackbox (github.com/casea1/blackbox). 0.25.0 was re-tested live on 8 Oct 2026 (findings.md, "0.25.0 quick re-test"). SEC1f, OS1, PPL1 and UI22 are confirmed fixed. Two small items are left, and neither blocks production.

## DET1b (must fix): refused deletes on Linux, from the command line only

`sudo rm /var/lib/blackbox/collector/stray-0.25.txt` was refused (Permission denied, drop-only inbox on CIFS). It still gives a High "claude deleted Blackbox's files: /usr/bin/rm …".

The audit log has only the `execve` of `rm` (success=yes). There is no unlink or PATH record: it's on CIFS, and the data-folder watch rules weren't installed. So the 0.25 check on the unlink result never applies.

- When the only evidence is the command line, say "ran rm on Blackbox's files: …" at **Medium**, with the detail "whether it worked isn't recorded".
- Keep **High** "deleted" only when a record shows the delete succeeded: PATH `nametype=DELETE` with the syscall `success=yes`, or the file missing at Blackbox's next run.
- Same for `wevtutil cl`-style command-only evidence, where it applies.
- **Tests:**
  - an execve-only `rm` record (Medium, "whether it worked isn't recorded");
  - execve plus a successful unlink (High);
  - execve plus a failed unlink (Medium, refused).

## LOG2 (backlog)

For a resent batch that was already imported, the per-file log line says "inbox: imported …". Say "already imported (sent again)" on that line.

## Done means

- DET1b is fixed, with tests.
- The new findings rows get "Fixed in".
- The version is bumped.
