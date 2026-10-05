Addendum to worker-prompt-3: four findings from live tests of 0.11.0 on 5 Oct 2026 (Ubuntu 26.04 sender → Server 2025 collector over SFTP). Please include them in the same release. Details are in findings.md (rows L12, U8b, U4b, A14b) and test-activity.log.

## L12 (High): the send unit's remount can never work on the SFTP route

There was a real 12-hour outage: the host restarted, the sshfs mount failed at boot, and 48 batches queued. Collection kept running, so L8 is fixed. But after the link came back, every scheduled `blackbox-send.service` run failed with "last mount error: read: Connection reset by peer", so the sender never recovers on its own.

- **Cause:** `ExecStartPre=-+/bin/mount /mnt/blackbox-inbox` runs inside the unit's `PrivateNetwork=yes` namespace. The `+` prefix lifts privilege and filesystem restrictions, but not the network namespace, so ssh can't reach the collector. Reproduced:
  - `systemd-run -p PrivateNetwork=yes /bin/mount /mnt/blackbox-inbox` gives "read: Connection reset by peer" and exit 1.
  - Without `PrivateNetwork` the mount succeeds, but the sshfs process belongs to the unit and is killed when the run ends.
- **Fix (tested live):** `ExecStartPre=-+/usr/bin/systemctl start <escaped mount unit>` (for example `mnt-blackbox\x2dinbox.mount`, from `systemd-escape -p --suffix=mount`). PID 1 then mounts it outside the sandbox, and the mount outlives the run. From inside `PrivateNetwork=yes` this mounted the folder, and the next `blackbox send` delivered all 53 batches.
- **Test:** add a CI test that runs the send unit with the mount unit stopped and the collector reachable.
- **Also:** `status` exited 0 while sends were failing and data had waited 11 hours. Make sure the 24-hour warning (exit 4) also fires when sends keep failing, and say "sending has failed since <time>".

## U8b: with sudo-rs, auditd stops are still "by root"

Live: "The audit service (auditd) was stopped by root" directly after "claude used sudo to run a command that can stop or weaken auditing: /usr/bin/systemctl stop auditd". With sudo-rs that command row comes from the journal (O1), but `stoppedBy()` only searches commands seen in the audit log. Make it also check the journal sudo lines (or the merged events), and add a fixture with sudo-rs journal lines plus `DAEMON_END … auid=0 pid=1`.

## U4b: login-message scripts are rows again on Ubuntu 26.04

One SSH login by `claude` (key auth, running a command) gave about 40 Low rows: "claude ran as root: /etc/update-motd.d/50-landscape-sysinfo", "uname -o", "cat /var/cache/motd-news", and so on. The chain is `sshd-session` → `sh -c -- /usr/bin/env -i PATH=… run-parts --lsbsysinit /etc/update-motd.d` → the scripts, and the U4 fold doesn't match it. Record that chain as a fixture and fold it into one row, or leave it out.

## A14b (minor): groupadd still adds two rows

`groupadd` still gives Low "claude changed the owner of a file (using groupadd)" and "…permissions of a file (using groupadd) to 0644" next to "created the group". Fold them into the group row, as was done for the temp-file rename.
