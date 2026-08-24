"""AArch64 fingerprint engine for beta-to-beta offset migration.

Turns a patch site in a base binary into a masked byte pattern (instruction
immediates wildcarded) and searches a target binary for it, verifying hits
with capstone disassembly.

Masking rationale: between beta builds, code shifts per compilation unit and
PC-relative/immediate fields change, but opcode + register + condition bits
of the instructions at a patch site are stable. Zeroing the volatile bits
makes the pattern survive the shift while keeping it specific enough to be
unique.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from capstone.arm64_const import ARM64_OP_REG
    _cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    _cs.detail = True
    CAPSTONE_AVAILABLE = True
except ImportError:  # pragma: no cover
    _cs = None
    ARM64_OP_REG = None
    CAPSTONE_AVAILABLE = False

DEFAULT_WINDOW = 32


def mask_insn(word: int) -> int:
    """Zero out PC-relative/immediate bits of an AArch64 instruction word.

    Keeps opcode, register, and condition bits. Unrecognized encodings pass
    through unchanged.
    """
    w24 = (word >> 24) & 0xFF

    # adrp / adr: immlo=bits[30:29], immhi=bits[23:5]
    if w24 & 0x1F == 0x10:
        return word & 0x9F00001F

    # b / bl: imm26=bits[25:0]
    if (word >> 26) in (0x05, 0x25):
        return word & 0xFC000000

    # cbz / cbnz: imm19=bits[23:5]
    if w24 in (0x34, 0x35, 0xB4, 0xB5):
        return word & 0xFF00001F

    # tbz / tbnz: bit-select=bits[23:19], imm14=bits[18:5]
    if w24 in (0x36, 0x37, 0xB6, 0xB7):
        return word & 0xFFE0001F

    # ldr (literal): imm19=bits[23:5]
    if w24 & 0x1F == 0x18:
        return word & 0xFF00001F

    # movz / movn / movk: hw=bits[22:21], imm16=bits[20:5]
    if w24 & 0x7F in (0x12, 0x52, 0x72):
        return word & 0xFF80001F

    # add/sub (immediate): shift=bits[23:22], imm12=bits[21:10]
    # must come BEFORE ldr/str-imm: subs (0xF1) also matches the ldr/str
    # top-bit pattern but needs the shift bits zeroed too
    if w24 & 0x7F in (0x11, 0x31, 0x51, 0x71):
        return word & 0xFF0303FF

    # ldr/str (unsigned immediate): imm12=bits[21:10] (keep opc bits[23:22])
    if w24 & 0xE0 == 0xE0:
        return word & 0xFFC003FF

    return word


def build_pattern(data: bytes, offset: int, window: int = DEFAULT_WINDOW) -> tuple[bytes, bytes]:
    """Build (pattern, mask) for a window of instruction words at offset.

    Mask byte 0xFF keeps the byte, 0x00 wildcards it. The window is walked
    in 4-byte words (patch sites are instruction-aligned).
    """
    end = min(offset + window, len(data))
    window_bytes = data[offset:end]

    pattern = bytearray()
    mask = bytearray()
    i = 0
    while i + 4 <= len(window_bytes):
        word = struct.unpack_from("<I", window_bytes, i)[0]
        masked = mask_insn(word)
        for shift in (0, 8, 16, 24):
            orig = (word >> shift) & 0xFF
            m = (masked >> shift) & 0xFF
            if orig == m:
                pattern.append(orig)
                mask.append(0xFF)
            else:
                pattern.append(0x00)
                mask.append(0x00)
        i += 4
    # trailing bytes (not a full word): keep verbatim
    for b in window_bytes[i:]:
        pattern.append(b)
        mask.append(0xFF)

    return bytes(pattern), bytes(mask)


def search_pattern(haystack: bytes, pattern: bytes, mask: bytes, aligned: bool = True) -> list[int]:
    """Return all offsets where (haystack & mask) == pattern.

    With aligned=True only 4-byte-aligned offsets are probed (instructions
    are aligned in both images), which is ~4x faster and filters unaligned
    false hits.
    """
    n = len(pattern)
    if n == 0 or len(haystack) < n:
        return []

    mv = memoryview(haystack)
    step = 4 if aligned else 1
    limit = len(haystack) - n
    hits = []
    first_pat = pattern[0]
    first_mask = mask[0]

    i = 0
    while i <= limit:
        if (mv[i] & first_mask) == first_pat:
            matched = True
            for j in range(1, n):
                if (mv[i + j] & mask[j]) != pattern[j]:
                    matched = False
                    break
            if matched:
                hits.append(i)
        i += step
    return hits


def _reg_operands(insn) -> tuple[str, ...]:
    regs = []
    for op in insn.operands:
        if getattr(op, "type", None) == ARM64_OP_REG:
            reg_id = getattr(op, "reg", None)
            if reg_id is not None:
                regs.append(insn.reg_name(reg_id))
    return tuple(regs)


def verify_site(target_data: bytes, t_off: int, base_data: bytes, b_off: int) -> Optional[bool]:
    """Check that the instruction at the candidate target site is the same
    instruction class (mnemonic + register operands) as the base site.

    Returns True (class match), False (mismatch), or None (not verifiable:
    no capstone, or capstone cannot decode either word — e.g. ASCII string
    sites, which are still strong evidence via the raw pattern itself).
    """
    if not CAPSTONE_AVAILABLE:
        return None
    b_insn = next(_cs.disasm(base_data[b_off:b_off + 4], 0), None)
    t_insn = next(_cs.disasm(target_data[t_off:t_off + 4], 0), None)
    if b_insn is None and t_insn is None:
        return None
    if b_insn is None or t_insn is None:
        return False
    if b_insn.mnemonic != t_insn.mnemonic:
        return False
    return _reg_operands(b_insn) == _reg_operands(t_insn)


def _site_word_value_changed(base_data: bytes, b_off: int,
                             target_data: bytes, t_off: int) -> bool:
    """True if the site's own instruction differs between builds only in
    masked (immediate) bits — i.e. the patch VALUE must be recomputed.
    Only the site word is checked so neighboring entries don't bleed in."""
    b_word = struct.unpack_from("<I", base_data, b_off)[0]
    t_word = struct.unpack_from("<I", target_data, t_off)[0]
    if b_word == t_word:
        return False
    return mask_insn(b_word) == mask_insn(t_word)


@dataclass
class MatchResult:
    name: str
    base_offset: int
    target_offset: Optional[int]
    delta: Optional[int]
    method: str
    confidence: float
    value_changed: bool
    old_value: str
    new_value: str
    candidates: list[int] = field(default_factory=list)
    disasm_class_ok: Optional[bool] = None
    suggested_value: str = ""


def migrate_site(base_data: bytes, target_data: bytes, base_offset: int,
                 name: str = "", window: int = DEFAULT_WINDOW) -> MatchResult:
    """Fingerprint the base site and find it in the target binary.

    Confidence tiers:
      0.95  unique masked hit + disasm class match
      0.90  unique hit at a non-instruction site (string/data — the raw
            pattern itself is strong evidence)
      0.60  hit found but disasm class mismatch (ambiguous, MED)
      0.30  multiple hits — candidates listed, manual review required
      0.00  no hit
    """
    if base_offset + 4 > len(base_data):
        return MatchResult(name, base_offset, None, None, "failed", 0.0, False, "", "", [])

    window = min(window, len(base_data) - base_offset)
    pattern, mask = build_pattern(base_data, base_offset, window)
    hits = search_pattern(target_data, pattern, mask)

    old_value = base_data[base_offset:base_offset + 4].hex()

    if not hits:
        return MatchResult(name, base_offset, None, None, "failed", 0.0, False, old_value, "")

    verified = [(h, verify_site(target_data, h, base_data, base_offset)) for h in hits]
    ok_hits = [h for h, v in verified if v is True]

    if len(hits) == 1 and ok_hits:
        target_offset = ok_hits[0]
        confidence = 0.95
        class_ok = True
    elif len(hits) == 1 and verified[0][1] is None:
        target_offset = hits[0]
        confidence = 0.90
        class_ok = None
    elif ok_hits:
        target_offset = ok_hits[0]
        confidence = 0.30
        class_ok = True
    else:
        target_offset = hits[0]
        confidence = 0.30 if len(hits) > 1 else 0.60
        class_ok = verified[0][1]

    value_changed = _site_word_value_changed(base_data, base_offset, target_data, target_offset)
    new_value = target_data[target_offset:target_offset + 4].hex()

    suggested = ""
    if value_changed:
        suggested = target_data[target_offset:target_offset + 4].hex()

    return MatchResult(
        name=name,
        base_offset=base_offset,
        target_offset=target_offset,
        delta=target_offset - base_offset,
        method="pattern",
        confidence=confidence,
        value_changed=value_changed,
        old_value=old_value,
        new_value=new_value,
        candidates=hits,
        disasm_class_ok=class_ok,
        suggested_value=suggested,
    )
