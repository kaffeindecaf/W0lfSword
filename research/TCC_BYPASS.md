# TCC Bypass Research Notes

> **Roadmap:** C2.1 — TCC bypass via kernel-level .db modification  
> **Status:** Research phase — no PoC. Estimated bounty: up to $100,000

---

## TCC Architecture

Transparency, Consent, and Control (TCC) is iOS's privacy database.
It stores which apps have been granted access to:

- Camera
- Microphone
- Photos
- Contacts
- Calendar
- Location
- Bluetooth
- Health data
- HomeKit

### Database Location

```
/private/var/mobile/Library/TCC/TCC.db
```

This is a SQLite database with tables:
- `access` — per-app permissions (service, client, auth_value, etc.)
- `access_overrides` — system-level overrides
- `admin` — MDM/admin policies

### Access Control

The TCC database is protected by:
1. **Filesystem permissions:** Only `mobile` user can read/write
2. **Sandbox:** App processes can't access `/private/var/mobile/Library/`
3. **Integrity:** TCCd (the daemon) caches entries in memory

---

## Attack Vectors

### 1. Direct Database Modification (requires sandbox escape)

With W0lfSword's sandbox escape (full filesystem R/W):

```sql
-- Grant camera access to Filza
INSERT INTO access (service, client, client_type, auth_value, auth_reason, ...)
VALUES ('kTCCServiceCamera', 'com.tigisoftware.Filza', 0, 2, 0, ...);
```

**Problem:** TCCd caches entries. Need to restart `tccd` or wait for cache expiry.

**Restart TCCd:** `killall tccd` — but this requires root/kernel access to signal the daemon.

### 2. Kernel Memory Modification

With kernel R/W, modify TCCd's in-memory cache directly:
1. Find TCCd's process via `proc_find_by_name("tccd")`
2. Locate the cache data structure in its heap
3. Add a fake entry for our bundle ID

**Problem:** The cache format is undocumented and may change between iOS versions.

### 3. System Hook (requires code injection into TCCd)

If we can inject a dylib into TCCd:
1. Hook `TCCAccessRequest` or equivalent
2. Return `allowed` for all requests

**Problem:** TCCd is a system daemon protected by AMFI. Requires `CS_PLATFORMIZED`
or kernel-level code signing bypass.

---

## Apple's Bounty Stance

Apple considers TCC bypass as part of their "Privacy" category:
- **TCC bypass requiring kernel access:** $50,000–$100,000
- **TCC bypass from sandbox (no kernel):** $100,000–$250,000
- **Zero-click TCC bypass:** Up to $250,000

W0lfSword falls into the "requiring kernel access" tier, which is lower-value
because Apple considers "kernel compromise → everything is accessible" as expected.

---

## Implementation Plan

### Phase 1: Database Modification (easier)

1. Achieve sandbox escape (already working)
2. Verify `/private/var/mobile/Library/TCC/` is accessible
3. SQLite: `INSERT INTO access ...`
4. Test: `AVCaptureDevice requestAccessForMediaType:` should return YES

### Phase 2: Cache Bypass (harder)

1. Stop TCCd: `proc_find_by_name("tccd")` → `task_terminate`
2. Modify database
3. Restart TCCd: System will relaunch it
4. Test camera grant

### Phase 3: In-Memory Cache Patching (hardest)

1. Find TCCd's heap cache structure
2. Add our entry via kernel write
3. Test immediately (no restart needed)

---

## Current Status

**W0lfSword position:** We have both kernel R/W and full filesystem access.
The technical capability exists, but the TCC bypass has not been attempted.

**Next step:** Add a TCC viewer/modifier to the W0lfSword script that:
1. Lists current TCC entries (read-only)
2. Offers to add a new entry for the current bundle ID
3. Tests the grant

---

*Last updated: 2026-08-10 — Research phase, no implementation*
