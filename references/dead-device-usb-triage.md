# Dead-device USB triage (first move after any crash)

A kernel panic, a watchdog kill or a resource kill ends with the same question:
where is the log? On 2026-09-11 the host answered that question with
`Could not connect to lockdownd: Invalid HostID (-21)` and every pull command
silently did nothing (0.12 `BUG.6`). This is the order that works.

## The two lockdownd failures that look like a dead phone

| Error | What it means | Fix |
| --- | --- | --- |
| `Could not connect to lockdownd: Mux error (-8)` | the USB / lockdown mux is wedged (a hung or locked device - a locked iPhone ignores SIGTERM, so a wedged `usbmuxd` stays wedged) | unlock the phone; if it stays dead, `sudo systemctl kill -s KILL usbmuxd` then `sudo systemctl start usbmuxd` |
| `Could not connect to lockdownd: Invalid HostID (-21)` | the device no longer trusts this host (the pairing record is stale, e.g. after a reboot or a reset) | unlock the phone and replug; tap Trust on the `Trust This Computer?` prompt and enter the passcode. If no prompt appears, `sudo rm /var/lib/lockdown/<UDID>.plist`, replug, then tap Trust on the prompt that comes back |

The two are not the same problem: `-8` is the mux, `-21` is the pairing. Neither
means the phone is broken, and force-restarting a `-21` device throws away the run
you were trying to observe.

## Order matters more than which row you land on

1. Unlock the phone (a locked device also blocks the pairing prompt).
2. Replug and tap **Trust** on the `Trust This Computer?` prompt.
3. Only if the prompt never appears: remove the stale host record.
   `<UDID>` is a filename you look up, never a guess - `ls -l /var/lib/lockdown/`
   lists one record per paired device, named for that device's UDID, and a record
   dated before the run you are debugging is the stale one.
4. Only if the mux stays wedged: kill and restart `usbmuxd`.

```bash
# 1. what the pairing records look like (and which one is stale)
ls -l /var/lib/lockdown/

# 2. the app's own log (the bundle id carries the sideloader's team suffix)
afcclient --container com.kaffeindecaf.w0lfterm.J8T95UQMW2 get Documents/FilzaTweak.log /tmp/wolfterm.log

# 3. kernel panics AND the three iOS resource reports (CPU, wakeups, disk writes)
idevicecrashreport -e /tmp/crash        # note: this MOVES the reports off the device

# 4. the same bundle id, discovered rather than guessed
pymobiledevice3 apps list --userspace | grep -i w0lfterm
```

## Reading what came back

`idevicecrashreport` returns `panic-full-*.ips` for a kernel panic,
`W0lfTerm.cpu_resource-*.ips` (CPU budget), `*.wakeups_resource-*`, and
`W0lfTerm.diskwrites_resource-*.ips` (disk-write budget - the report that read
`1073.75 MB of file backed memory dirtied over 1083 seconds` against a
`12.43 KB per second over 86400 seconds` limit). Read `Action taken:` in each:
`none` is a warning, a kill is the next step.

Live streaming instead of a pull: `idevicesyslog | grep -i wolfsword` (the app's
`os_log` subsystem is `com.kaffeindecaf.w0lfsword`).

The app-side copy of this section is `W0lfTerm/README.md` -> "Pulling logs over
USB"; this file is the engine-repo copy so the first move after a crash lives
next to the exploit code too.
