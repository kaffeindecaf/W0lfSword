# K4.7 - CVE-2025-46285 localized: `struct vm_map.timestamp` widened 32 -> 64 bit

Laptop only. No device, no symbols, no patched-build source. The fix was
localized from public kernelcaches plus public xnu source tags.

Raw evidence, one file per invocation: `docs/verification/2026-09-29-kc-localize/`
(hashes in its `SHA256SUMS`). Reproduce the whole bundle with:

    scripts/kc_localize.sh .w0lfsword/kernelcaches/macho_18.7.2 \
                           .w0lfsword/kernelcaches/macho_18.7.3

## 1. What the CVE is

iOS 18.7.3 / iPadOS 18.7.3 security notes, released December 12 2025
(support.apple.com/en-us/125885), second Kernel entry:

    Impact: An app may be able to gain root privileges
    Description: An integer overflow was addressed by adopting 64-bit timestamps.
    CVE-2025-46285: Kaitao Xie and Xiaolong Bai of Alibaba Group

The same release carries a second Kernel entry that is *not* this one:

    Impact: An app may be able to elevate privileges
    Description: A logic issue was addressed with improved checks.
    CVE-2025-43512: Andreas Jaegersberger & Ro Achterberg of Nosebeard Labs

NVD classifies CVE-2025-46285 as CWE-190 (integer overflow), fixed in iOS 18.7.3
and iOS 26.2. "Adopting 64-bit timestamps" names the fix, which makes the target
a 32-bit counter that became 64-bit - and makes the release pair 18.7.2 -> 18.7.3
(and 26.1 -> 26.2 on the other line) the diff to run.

## 2. Inputs

| product | build | kernel version string from the binary | mach-o | sha256[0:16] |
| --- | --- | --- | --- | --- |
| 18.7.2 | 22H124 | `xnu-11417.140.69.702.20~1` (Oct 15 2025) | `.w0lfsword/kernelcaches/macho_18.7.2` | `f102a72b2fec2eb7` |
| 18.7.3 | 22H217 | `xnu-11417.140.69.704.2~1` (Nov 5 2025) | `.w0lfsword/kernelcaches/macho_18.7.3` | `e3172e5364910053` |
| 26.1 | 23B85 | `xnu-12377.42.6~55` | `.w0lfsword/kernelcaches/macho_26.1` | `2ba97f893395eedb` |
| 26.2 | 23C57 | `xnu-12377.62.10~1` | `.w0lfsword/kernelcaches/macho_26.2` | `3dc5b2d30f6597bc` |

All four are XPF-decoded kernelcache Mach-Os (`tools/xpf-cli`), T8020 for the
18.x pair, T8110 for the 26.x pair.

Note the 18.x pair shares one base version (`11417.140.69`) and differs only in
build suffix `702.20` -> `704.2`. That is the shape of a security-only patch on
the same base, and it is why no xnu tag exists for the fixed 18.x source.

## 3. Method: content matching, not address matching

A positional diff of two kernelcaches is worthless: every build lays functions
out in a different order, and a large fraction of bytes differ for reasons that
have nothing to do with the fix. So `scripts/kc_funcdiff.py`:

1. enumerates candidate function starts per executable segment (targets of `bl`),
2. decodes each body with capstone,
3. canonicalizes it - register numbers dropped, `adrp+add` pairs resolved to a
   single page-relative token with the low 12 bits *kept* (so a changed string or
   object reference still shows up), branch destinations resolved to a token,
4. keys each body by the hash of that canonical text, and
5. reports bodies whose key exists in one build and not the other.

The pairing step (`scripts/kc_pairs.py`) only affects presentation: it diffs the
changed bodies in address order, smallest diff first.

Two real bugs were found and fixed while building this, both of which had
silently corrupted earlier numbers in this work:

- capstone's decoder **stops at the first word it cannot decode**, and kernel
  text has literal pools and jump tables inline. Without `skipdata = True` a body
  was compared only up to its first data blob and a whole-segment sweep ended a
  few KB in. Turning it on moved the kernel match count from 14,348 to 15,958
  candidate functions, with the same 98 changed bodies.
- the `adrp` resolver must **invalidate the destination register** on every
  `adrp`, otherwise its page base leaks forward and later references point at the
  previous page. This produced ~1.4 KB of phantom delta (one kext looking
  changed when it was not).

## 4. Result: one struct edit, 98 function bodies

Kernel text (`com.apple.kernel`, `__TEXT_EXEC`), 18.7.2 -> 18.7.3:

    funcs old=15958 new=15958 identical=15860 | only-old=98 only-new=98

So 98 of 15,958 kernel function bodies differ, and those 98 are the **entire**
xnu code delta of the release. Whole-kernelcache text (the root `__TEXT_EXEC`
container: kernel plus all 224 kexts):

    funcs old=100516 new=100516 identical=100416 | only-old=100 only-new=100

100 changed bodies: the same 98 kernel bodies, one body in
`com.apple.security.sandbox`, and one partition-boundary artifact between the two
views (the container view partitions the shared region slightly differently).
Every other executable segment of the kernel is unchanged: `__TEXT`,
`__PPLTEXT`, `__PPLTRAMP` and `__KLD` report 0 candidate functions and 0 changes
(`regions_zero.log`).

### 4.1 The three edit shapes

Of the 98 paired diffs: 68 contain the map-version widening, 34 contain the
`sizeof` constants, 17 contain both. The shapes:

    ldr   w8, [x20, #0xdc]         ->  ldr   x8, [x20, #0xe0]
    add   w8, w8, #1                   add   x8, x8, #1
    str   w8, [x20, #0xdc]             str   x8, [x20, #0xe0]

    adds  x9, x1, #0xf0           ->  adds  x9, x1, #0xf8      (sizeof, and the
    adds  x8, x0, #0xf1           ->  adds  x8, x0, #0xf9       bound is exclusive)

and the pre-fix packed form, where flags and the counter were updated as one
64-bit unit and the compiler reached the upper 32-bit lane with vector moves
(`ldr d0, [x0, #0xd8]` / `str d0, ...`), splits into two scalar accesses.

A wide spread of changed-line counts (2 ... 238, one 3100) is expected and does
not weaken the localization: the canonicalization deliberately keeps the low 12
bits of page-relative references, so any *other* legitimate content shift inside
a changed body (a moved string, table or literal) shows up in the same diff. The
function *set* is decided by content hash, not by pairing, so it is unaffected.

### 4.2 The struct: zone "maps"

Zone registration is recognizable by its string argument and the element size
passed next to it. In the 18.x pair there are four zones in a row; the first is
`VM_MAP_ZONE_NAME` (`osfmk/vm/vm_map.c:938`, `#define VM_MAP_ZONE_NAME "maps"`),
registered as `zone_create_ext(VM_MAP_ZONE_NAME, sizeof(struct _vm_map), ...)`
(`vm_map.c:1321` in xnu-11417.140.69):

    18.7.2   add x0, x0, #0x6e0  ; "maps"      mov w1, #0xf0    240 bytes
    18.7.3   add x0, x0, #0x6e4  ; "maps"      mov w1, #0xf8    248 bytes

and the neighbours are unchanged, which rules out a general zone-layout shift:

    "VM map entries"  0x50   0x50
    "VM map holes"    0x20   0x20
    "VM map copies"   0x48   0x48

Same measurement on the 26.x pair, which localizes the fix on second build line:

    26.1     mov w1, #0xf0    240 bytes     (pre-fix)
    26.2     mov w1, #0xf8    248 bytes     (post-fix)

`+8` on an `0xf0` struct whose counter moved from a 32-bit field at offset `0xdc`
to an 8-byte aligned `0xe0` is exactly `+4` of field and `+4` of padding. It is
one struct growing by one widened field.

## 5. Source confirmation

Apple publishes only base-version xnu tags, so the tags bracket the builds rather
than matching them. Diffing the published trees:

| tree | `struct vm_map.timestamp` | `vm_map_version_t.main_timestamp` |
| --- | --- | --- |
| `xnu-11417.140.69` (base of both 18.7.2 and 18.7.3) | `vm_map_xnu.h:461` `unsigned int timestamp;` | `:500` `unsigned int main_timestamp;` |
| `xnu-12377.41.6` (base of 26.1) | `vm_map_xnu.h:479` `unsigned int timestamp;` | `:567` `unsigned int main_timestamp;` |
| `xnu-12377.61.12` (between 26.1 and 26.2) | `vm_map_xnu.h:479` `uint64_t timestamp;` | `:567` `uint64_t main_timestamp;` |

The whole diff of `osfmk/vm/vm_map_xnu.h` between `xnu-12377.41.6` and
`xnu-12377.61.12` is **two lines**:

    @@ -476,7 +476,7 @@
    -	unsigned int            timestamp;          /* Version number */
    +	uint64_t timestamp;          /* Version number */
    @@ -564,7 +564,7 @@
    -	unsigned int    main_timestamp;
    +	uint64_t    main_timestamp;

Same line numbers, same comment, no other change in that header. That is the
source-side fingerprint of CVE-2025-46285, and it agrees with the binary in both
directions: the struct grew by 8 bytes, and the compiler's packed
`flags|timestamp` update became two scalar accesses.

The 18.x line has no published post-fix tree (`11417.140.69` is the newest 18.x
tag and is still 32-bit), so for 18.7.3 the binary is the only evidence - which is
why the 26.x binaries were measured too, to check the same struct and the same
`+8` instead of trusting the 18.x binary alone.

## 6. Why this field

`map->timestamp` is the vm_map lock version. It is incremented on every exclusive
unlock of the map (`vm_map_unlock`, `vm_map_lock_write_to_read`,
`vm_map_entry_wait`, `vm_map_entry_unwait`) and is the token that
`vm_map_version()` publishes and `vm_map_verify()` checks - the optimistic
validation used by the copy/remap/lookup paths that hold a map reference across a
lock drop (for example `vm_remap`, `vm_map_copy_overwrite`, and the `vm_map_lookup`
retry loops).

As a 32-bit counter the version can wrap back onto a value an in-flight
operation already snapshotted, so a "map unchanged" check passes over a map that
did change, and the operation proceeds with a stale `vm_map_entry_t` or
`vm_object_t`. The privileged/hostile-input side of that is what "An app may be
able to gain root privileges" describes; `main_timestamp` is `unsigned int` in the
same struct, which is why the fix widens both.

It is a 64-bit widening, not a check: there is no new comparison to find. That is
why the delta looks like "the same code, 4 bytes to the right" in 98 places
instead of a new bounds test.

## 7. What this proves, and what it does not

Proves:

- the xnu code delta of iOS 18.7.3, at function granularity: 98 bodies, all of
  them the `struct _vm_map` widening
- the structure and field: zone `"maps"` = `struct _vm_map`, element size
  0xf0 -> 0xf8, counter at `0xdc` -> `0xe0`, in both the 18.x and 26.x pairs
- the source change: two lines, `unsigned int` -> `uint64_t`, on both
  `timestamp` and `main_timestamp`
- that iOS 26.2 carries the same fix, from binaries rather than from the advisory

Does not prove:

- the trigger. Nothing here shows the cheapest path to wrap the 32-bit counter on
  a live 18.7.2 or 26.1 device; that needs a device (and is the remaining,
  hardware-bound half of K4.7).
- attribution of the *other* Kernel entry in the same release. CVE-2025-43512 is
  in the same 18.7.3 advisory and my code-diff has no candidate for it: every
  kernel body except the 98 timestamp sites is content-identical, and those 98 are
  fully accounted for. The one non-kernel changed body
  (`com.apple.security.sandbox`, 4992 bytes) is the only remaining candidate in
  the text, so 43512's fix is either that body, a data-only (const table) change,
  or outside the kernelcache text entirely. That is open, and it bounds this
  finding: "the 18.7.3 kernel text delta is exactly the 46285 fix" is a statement
  about text, not about the whole release.
- anything about data/const segments. The method diffs code; a change in
  `__TEXT.__const`, `__DATA_CONST` or a trustcache blob would not appear.

## 8. Reproduce

    # function-level delta of the kernel and of all kernelcache text, plus the
    # instruction diff of every changed body and hashes of everything:
    scripts/kc_localize.sh .w0lfsword/kernelcaches/macho_18.7.2 \
                           .w0lfsword/kernelcaches/macho_18.7.3

    # same, second release line (fix lands in 26.2):
    scripts/kc_localize.sh .w0lfsword/kernelcaches/macho_26.1 \
                           .w0lfsword/kernelcaches/macho_26.2

    # the zone size, by string xref with labeled disassembly:
    scripts/kc_xref.py .w0lfsword/kernelcaches/macho_18.7.2 \
        --find-string "VM map copies" --window 40 --seg com.apple.kernel
    scripts/kc_xref.py .w0lfsword/kernelcaches/macho_18.7.3 \
        --disasm --at 0xfffffff0085eb64c --size 0x120

    # tool self-test (canonicalization + matching rules):
    scripts/kc_funcdiff.py --selftest
