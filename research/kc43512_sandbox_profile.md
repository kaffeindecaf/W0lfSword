# CVE-2025-43512: 112 bytes of built-in sandbox profile, not kernel code

Laptop only, no device. Found while attributing the 18.7.3 kernelcache delta for
K4.7: the release's second Kernel entry is not in the changed kernel text at all.
Evidence: `docs/verification/2026-09-29-kc43512-sandbox-profile/`.

## 1. The gap this closes

iOS 18.7.3 / iPadOS 18.7.3 (support.apple.com/en-us/125885, 2025-12-12) has two
Kernel entries:

    Impact: An app may be able to elevate privileges
    Description: A logic issue was addressed with improved checks.
    CVE-2025-43512: Andreas Jaegersberger & Ro Achterberg of Nosebeard Labs

    Impact: An app may be able to gain root privileges
    Description: An integer overflow was addressed by adopting 64-bit timestamps.
    CVE-2025-46285: Kaitao Xie and Xiaolong Bai of Alibaba Group

K4.7 localized the second one: `struct vm_map.timestamp` widened to 64 bits,
98 changed xnu function bodies, which is the *entire* kernel text delta of the
release. That leaves the first entry with no code candidate - and a release pair
where the text diff is fully explained by one fix is a good place to look for a
fix that is not code.

The whole-kernelcache text diff (kernel + all 224 kexts, 100,516 functions per
side) has exactly one changed body outside `com.apple.kernel`:

    com.apple.security.sandbox  __TEXT_EXEC  0xfffffff009e62ba4  4992 bytes

## 2. That body carries only a length

The body is byte-identical to the 18.7.2 version except for one immediate:

    0x1090  mov  w3, #0x5d6          ->  mov  w3, #0x646      (+0x70 = +112)
    0x1094  movk w3, #0xb, lsl #16      (same)
    0x1098  bl   #0xfffffff009e6ea00    (same target)

The full call setup, identical in both builds except for that immediate:

    x0 = 0xfffffff007de32c0   (__DATA_CONST+0x24d8, a zeroed struct)
    x1 = "builtin collection"
    x2 = __TEXT+0x255d0       (code pointer)
    x4 = pacia(__TEXT+..., 0x2abe)   (PAC-signed code pointer)
    w3 = 0x000b05d6 -> 0x000b0646    (the changed 32-bit constant)
    bl   0xfffffff009e6ea00

So the function registers a "builtin collection" - the sandbox kext's built-in
profile data - and the only thing that changed in the code is the number handed
to that registration: it grew by exactly 112.

## 3. The data grew by exactly 112 bytes

Segment sizes of `com.apple.security.sandbox`:

| segment | 18.7.2 | 18.7.3 | delta |
| --- | --- | --- | --- |
| `__TEXT` | 0x1c49ad | 0x1c4a1d | **+0x70 (+112)** |
| `__TEXT_EXEC` | 0x31634 | 0x31634 | 0 |
| `__DATA` | 0x4000 | 0x4000 | 0 |
| `__DATA_CONST` | 0x4ee0 | 0x4ee0 | 0 |
| `__LINKEDIT` | 0x55aa9 | 0x55aa9 | 0 |

`scripts/kc_datainsert.py` then locates where, inside `__TEXT`, those bytes went:
everything before `__TEXT+0xce767` is byte-identical, and everything from there
matches the 18.7.2 bytes shifted by 112. So it is a single 112-byte insertion at
VA `0xfffffff0078078c7`, not a rewrite.

    context before : ..yCrashReporter/PersistentConnection/com.apple.syncdefaultsd....
    inserted bytes : gs/.kPersistentConnection/com.apple.syncdefaultsd..yCrashReporter/
                     PersistentConnection/com.apple.syncdefaultsd..
    context after  : .U...../Library/Caches/com.apple.nsurlsessiond/Downloads/com.app

Readable ASCII inside the inserted window, with the compiled-profile control
bytes (`.`, `0x0f`, `0x80 0x0a`) between the literals:

    PersistentConnection/com.apple.syncdefaultsd
    CrashReporter/PersistentConnection/com.apple.syncdefaultsd
    .../Library/Caches/com.apple.nsurlsessiond/Downloads/...   (context, unchanged)

These are sandbox profile path literals, i.e. the insertion is a rule/pattern
change in the compiled built-in profile. The code change is only the "how many
bytes is that collection now" constant, and the literal table after the
insertion shifts by the same 112 - which is why the same number appears in both
places.

## 4. The same mechanism on the 26.x line

Same kext, 26.1 -> 26.2: `__TEXT` grows 0x1e1d6f -> 0x1e529f (**+0x3530 =
+13,616 bytes**) while `__TEXT_EXEC` is unchanged in size, and the kext's text
delta is three bodies:

| body | change |
| --- | --- |
| 0xfffffff00a56dd64 (5096 B) | six length-like immediates, all grown: `w3 0x5b21 -> 0x7951`, `w3 0x0af71e -> 0x0b0b3e`, `w9 0x28d1 -> 0x2bb9`, `w9 0x2f58 -> 0x3158`, `w8 0x297 -> 0x2c3`, ... |
| 0xfffffff00a57d454 (884 B) | `mov w9, #0x383 -> #0x3bd` (+0x3a) |
| 0xfffffff00a55a378 (492 B) | `ldr x8, [x8, #D]` -> `ldr x8, [x8]` (a struct field offset, i.e. a layout change) |

Same pattern: the profile data grows, the code follows with new sizes. The
18.x release grew the collection by 112 bytes, the 26.x one by 13,616.

## 5. Attribution

Apple's 18.7.3 page has no "Sandbox" section, and 46285 accounts for the whole
xnu text delta. CVE-2025-43512 is the only remaining Kernel entry in the same
release, and its impact line ("an app may be able to elevate privileges", "a
logic issue ... addressed with improved checks") is what a built-in profile
change looks like: the *policy* text grows, the code does not. The sandbox kext
is loaded from the kernelcache, so Apple files it under Kernel.

This is inference from elimination, not a quote - the advisory never names a
component. The stronger, quoted part of this note is the mechanism: a security
release that changed 98 xnu bodies (all one struct widening) also changed one
kext by growing its built-in profile by 112 bytes, and the only code edit in that
kext is the length constant for that data.

## 6. What this proves, and what it does not

Proves:

- the 18.7.3 kernelcache has exactly three kinds of change: 98 xnu bodies (one
  struct widening), one sandbox kext body (one constant), and +112 bytes of
  sandbox profile data at a precise offset
- the insertion point, its exact bytes, and that the tail shifts by exactly 112
- that the sandbox kext's `__TEXT` grows by 13,616 bytes on the 26.x line too,
  with the same "sizes in code, data in the segment" pattern

Does not prove:

- which rule or operation was added or tightened. The surrounding bytes are
  compiled profile data (SBPL); decoding the encoding around
  `__TEXT+0xce767` is a separate job, and that decode is what would say whether
  the pre-fix profile allowed the privilege path 43512 describes.
- the attribution to 43512, for the reason in §5.
- anything about behaviour: no profile was evaluated and no device was used.

## 7. Repro

    # where the data went (single insertion, exact bytes)
    scripts/kc_datainsert.py .w0lfsword/kernelcaches/macho_18.7.2 \
        .w0lfsword/kernelcaches/macho_18.7.3 \
        --owner com.apple.security.sandbox --seg __TEXT --context 64 --hex

    # the one changed body in that kext, and the 26.x cross-check
    scripts/kc_pairs.py .w0lfsword/kernelcaches/macho_18.7.2 \
        .w0lfsword/kernelcaches/macho_18.7.3 --owner com.apple.security.sandbox
    scripts/kc_pairs.py .w0lfsword/kernelcaches/macho_26.1 \
        .w0lfsword/kernelcaches/macho_26.2 --owner com.apple.security.sandbox

    # self-test of the insertion locator (synthetic inserts, in-place rewrite)
    scripts/kc_datainsert.py --selftest
