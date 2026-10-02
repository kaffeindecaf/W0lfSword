# tweaks/parity.md - tweak-menu parity vs Mugunghwa + iDevice-Toolkit

_Source: the archived per-repo deep reads in `referenceforAI/RESEARCH.md`
(sections "Mugunghwa" and "iDevice-Toolkit"). Both upstream trees were deleted
from `referenceforAI/` on 2026-08-24; the provenance table at the top of
RESEARCH.md carries the clone URLs and commits, so a fresh clone re-checks any
line-level claim below. Catalog state is `tweaks/catalog.json` (13 rows:
11 available, 2 planned)._

## What the two references actually are

**Mugunghwa** (s8ngyu, TrollStore .ipa, iOS 14-16 era) has no kernel bug. Its
power is a TSUtil-lineage root helper: `posix_spawnattr_set_persona_np(99)` +
`set_persona_uid_np(0)` spawns a bundled helper whose entitlements include
`platform-application` and absolute-path read-write on `/`. Theming is then
plain file work: user-app icons by rewriting `Assets.car` renditions (CoreUI
`saveEditedImage` + `catalog.recompile()`, backup to `bak.car`) or legacy
`CFBundleIconFiles` PNGs, system-app icons via `WebClips` dirs, device look by
rewriting the MobileGestalt cache (`ArtworkDeviceSubType`), passcode theming via
`writeToCPBitmapFile:flags:`. Respring is `killall("SpringBoard")` over
KERN_PROC.

**iDevice-Toolkit** (GeoSn0w, 16.0-18.3.2) is a SwiftUI app around a 65-line
userspace primitive, CVE-2025-24203: map the file read-only, set
`VM_BEHAVIOR_ZERO_WIRED_PAGES`, `mlock`, `vm_deallocate`, then keep the
dangling PTE as a write window into the page cache. Its "tweaks" are paths, not
code: overwrite a SpringBoard asset in place, respring, reboot to revert.
Patched in 18.4+, so the mechanism is not ours to adopt.

## Feature matrix

### iDevice-Toolkit

| feature | their technique | ours | status |
|---|---|---|---|
| hide dock | wipe `CoreMaterial.framework/dock{Dark,Light}.materialrecipe` in RAM | `hide_dock` (hook) | available |
| hide home bar | rewrite `MaterialKit.framework/Assets.car` | `hide_home_bar` (hook) | available |
| hide folder background | wipe `SpringBoardHome.framework/folder{Dark,Light}.materialrecipe` | `transparent_folders` (hook) | available |
| camera shutter sound | overwrite `Audio/UISounds/photoShutter.caf` | - | not in catalog |
| other path lists | 10 entries in their `default_tweaks.json` | covered in spirit by the three hook tweaks | partial |
| `usr/lib/dyld` entry | forced panic / reboot | - | will not replicate |

Same feature, different owner: they rewrite the asset because all they have is a
write window into the page cache; our catalog hooks the reader instead, which
needs no file write at all.

### Mugunghwa

| feature | their technique | ours | status |
|---|---|---|---|
| badge colour | SpringBoard badge view tint | `badge_colors` | planned |
| passcode theming | CPBitmap button images | `passcode_theming` | planned |
| icon theming (user apps) | `Assets.car` rendition rewrite, PNG fallback | `custom_icons` (PNG at `/var/mobile/Documents/Icons/<bundleid>.png`) | available |
| icon theming (system apps) | `WebClips` dirs + `com.apple.private.WebClips.read-write` | - | gap |
| home gesture / device look | MobileGestalt cache `ArtworkDeviceSubType` | `mobilegestalt` CLI (chain F, kernel route) | shipped in the CLI, not as a catalog tweak |
| respring after apply | `killall("SpringBoard")` over KERN_PROC | `tweaks install` deploys + resprings | parity |
| backup / restore one theme | `bak.car` / `bak.png` swap, delete WebClips | - | gap |

## What we will not replicate, and why

- **The persona-99 root helper.** It needs TrollStore's persistent signing plus
  `platform-application` and absolute-path entitlements, which a sideloaded
  bundle id cannot hold. Our delivery is kernel R/W or a hook, never a
  privileged sidecar.
- **CVE-2025-24203 itself.** Fixed in 18.4+, dead on every device the kernel
  gate lets through, so adopting it would add a second primitive with a shorter
  window than DarkSword.
- **The WebClip system-app icon route.** Needs the WebClips container write
  entitlement; our honest equivalent is an icon-cache or `Assets.car` rewrite
  from the escaped process, i.e. the same feature with a different owner.
- **The `usr/lib/dyld` path in iDevice-Toolkit's list.** It is a deliberate
  panic ("force reboot"), exactly the outcome the crash counter and auto-disable
  flag exist to prevent.

## Build order

Ordering rule: hook-only tweaks first (a substrate hook writes no files, so no
SSV/vnode path and no backup story), then the path rewrites that need kernel R/W
plus a restore, then the items that need a deliverable we do not have.

1. `custom_icons` (K3.7) - shipped 2026-10-02: `tweaks/templates/custom_icons.xm`
   hooks `SBIconView -setIcon:` and pushes a PNG-per-bundleid image into the
   icon's own image views; it reads `/var/mobile/Documents/Icons/<bundleid>.png`
   and writes nothing, so the revert is "delete the dir + respring". The
   `Assets.car` rendition rewrite is the follow-up, once the CoreUI route is
   verified on a device - it needs the write window this hook does not.
2. `badge_colors` - Mugunghwa's simplest feature, one SpringBoard badge view
   hook, no file writes.
3. `passcode_theming` - same class as `badge_colors`, but the passcode keypad
   classes are less stable across iOS versions; verify per version before
   shipping.
4. Camera shutter sound (new catalog row) - the first path tweak: needs the
   SSV/vnode write path plus a backup file, and is the cheapest way to prove
   that whole workflow end to end.
5. System-app icon theming - last, because the honest version needs an icon
   cache or `Assets.car` rewrite, not a WebClip dir.

Both `badge_colors` and `passcode_theming` carry `ios_max 18.5` in the catalog,
inherited from Mugunghwa's era (TrollStore/helper delivery). Their hook targets
need a re-check against 26.x before either row moves out of `planned`.
