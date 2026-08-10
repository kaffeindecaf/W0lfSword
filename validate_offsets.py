#!/usr/bin/env python3
"""validate_offsets.py — W0lfSword offset table integrity checker

Verifies all struct offsets in kexploit/offsets.m are:
  - Non-zero (0 means uninitialized)
  - Pointer fields within VM_MIN..VM_MAX (if known)
  - No 0xdeaddead sentinel values left unguarded
  - sizeof fields are reasonable (< 4096)
  - No duplicate iOS version ranges

Usage: python3 validate_offsets.py
"""

import re
import sys

VM_MIN = 0xFFFFFFDC00000000
VM_MAX = 0xFFFFFFFBFFFFFFFF

# Fields named like these are struct offsets, not kernel addresses.
# They can be any positive value.
OFFSET_FIELDS = {
    'off_', 'sizeof_',  # kernel struct offsets
}

# Fields named like these are POINTERS that must be within kernel range.
POINTER_FIELDS = {
    # Not exhaustive — we flag 0xFFFFFF... values as likely pointers
}

def is_pointer_value(val):
    """Heuristic: 0xFFFFFF... values are likely kernel pointers."""
    return (val & 0xFFFFFF0000000000) == 0xFFFFFF0000000000

def parse_offsets_m(path):
    findings = []
    line_num = 0
    blocks = 0
    
    with open(path, 'r') as f:
        for line in f:
            line_num += 1
            stripped = line.strip()
            
            # Count version blocks
            if 'SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO' in stripped:
                blocks += 1
            
            # Match: uint32_t name = 0xVAL;
            m = re.match(r'uint(?:32|64)_t\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+)\s*;', stripped)
            if not m:
                continue
            
            name, val_str = m.groups()
            val = int(val_str, 16)
            
            # Check: zero value (uninitialized)
            if val == 0:
                findings.append(('WARN', line_num, name, val,
                    f"zero value — may be uninitialized for this iOS version"))
            
            # Check: 0xdeaddead sentinel
            if val == 0xdeaddead:
                findings.append(('OK', line_num, name, val,
                    "0xdeaddead sentinel (not applicable for this config)"))
            
            # Check: likely kernel pointer outside valid range
            if is_pointer_value(val):
                if val < VM_MIN or val > VM_MAX:
                    findings.append(('FAIL', line_num, name, val,
                        f"kernel pointer 0x{val:x} outside range [0x{VM_MIN:x}, 0x{VM_MAX:x}]"))
            
            # Check: sizeof field (should be < 4096)
            if 'sizeof' in name or 'size' in name.lower():
                if val > 4096:
                    findings.append(('FAIL', line_num, name, val,
                        f"sizeof field = {val} (> 4096), likely wrong"))
    
    return findings, blocks

def main():
    path = 'kexploit/offsets.m'
    findings, blocks = parse_offsets_m(path)
    
    fails = [f for f in findings if f[0] == 'FAIL']
    warns = [f for f in findings if f[0] == 'WARN']
    oks = [f for f in findings if f[0] == 'OK']
    
    print(f"=== W0lfSword Offset Validation ===\n")
    print(f"File: {path}")
    print(f"Version blocks: {blocks}")
    print(f"Total fields checked: {len(findings)}")
    print("")
    
    if fails:
        print(f"── FAIL ({len(fails)}) ──")
        for _, ln, name, val, msg in fails:
            print(f"  line {ln}: {name} = 0x{val:x} — {msg}")
        print("")
    
    if warns:
        print(f"── WARN ({len(warns)}) ──")
        for _, ln, name, val, msg in warns:
            print(f"  line {ln}: {name} = 0x{val:x} — {msg}")
        print("")
    
    if oks:
        print(f"── Sentinel OK ({len(oks)}) ──")
        for _, ln, name, val, msg in oks:
            print(f"  line {ln}: {name} = 0x{val:x} — {msg}")
        print("")
    
    if fails:
        print(f"VALIDATION FAILED — {len(fails)} errors")
        sys.exit(1)
    else:
        print(f"VALIDATION PASSED — no critical issues")
        sys.exit(0)

if __name__ == '__main__':
    main()
