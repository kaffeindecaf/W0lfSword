#!/usr/bin/env python3
"""T16 independent cross-checks for BUG.3 / BUG.4 / BUG.5.

The shared lint (scripts/check_scan_budget_cancel_writes.py) is the primary
checker; this file is a second, independently written reader of the same two
trees plus the linked app binary, so a lint that drifted from the tree (or a
claim that only exists in the roadmap prose) has to pass twice. Host only: it
opens text files and one Mach-O. No device command.

Usage: python3 invariant_check.py <repo-root> <app-root> <linked-binary>
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(sys.argv[1])
APP = pathlib.Path(sys.argv[2])
BIN = pathlib.Path(sys.argv[3])

ok = fail = 0

def check(name, cond, detail=""):
    global ok, fail
    if cond:
        print("ok   %s%s" % (name, ("  [%s]" % detail) if detail else ""))
        ok += 1
    else:
        print("FAIL %s%s" % (name, ("  [%s]" % detail) if detail else ""))
        fail += 1

def read(p):
    return p.read_text(encoding="utf-8", errors="replace")

def strip_comments(src):
    """Drop //-comments (and /* */ blocks are not used in the shipped strings
    this file asserts on). Rationale: history comments in these trees quote the
    OLD wording verbatim - 'the old #define ... 120 lived here', 'zero kernel
    writes read as safe' - so a raw grep over the file confuses the record of
    the bug with the shipped string."""
    out = []
    for line in src.splitlines():
        s = line.strip()
        if s.startswith("//") or s.startswith("*") or s.startswith("/*"):
            continue
        out.append(line)
    return "\n".join(out)

eng_m = read(ROOT / "kexploit/kexploit_opa334.m")
eng_m_code = strip_comments(eng_m)
eng_h = read(ROOT / "kexploit/kexploit_opa334.h")
settings = read(APP / "term_settings.m")
settings_code = strip_comments(settings)
bridge = strip_comments(read(APP / "term_bridge.m"))
tvc = strip_comments(read(APP / "TerminalViewController.m"))
raw = BIN.read_bytes()

# ---- BUG.3: one budget, four places that must agree -------------------------
eng_default = re.search(r"#define EXPLOIT_SCAN_BUDGET_SEC (\d+)", eng_m_code)
app_default = re.search(r"static int g_scanBudget = (\d+);", settings)
check("BUG.3: the engine has a default budget",
      bool(eng_default), eng_default.group(0) if eng_default else "not found")
check("BUG.3: the app has the same default budget",
      bool(app_default) and bool(eng_default) and
      app_default.group(1) == eng_default.group(1),
      "engine %s / app %s" % (eng_default.group(1) if eng_default else "?",
                              app_default.group(1) if app_default else "?"))
check("BUG.3: the default is the one that fits the walk (600 s, not the old 120)",
      bool(eng_default) and int(eng_default.group(1)) == 600)

bmin = re.search(r"#define KEXPLOIT_SCAN_BUDGET_MIN (\d+)", eng_h)
bmax = re.search(r"#define KEXPLOIT_SCAN_BUDGET_MAX (\d+)", eng_h)
setter = re.search(r"void kexploit_set_scan_budget\(int seconds\) \{(.*?)\n\}",
                   eng_m_code, re.S)
check("BUG.3: the budget is clamped to [MIN, MAX]",
      bool(bmin) and bool(bmax) and bool(setter) and
      "KEXPLOIT_SCAN_BUDGET_MIN" in setter.group(1) and
      "KEXPLOIT_SCAN_BUDGET_MAX" in setter.group(1),
      "header %s..%s, both bounds applied in the setter" %
      (bmin.group(1) if bmin else "?", bmax.group(1) if bmax else "?"))
check("BUG.3: the setter writes the same atomic the accessor reads",
      "atomic_store_explicit(&g_scanBudgetSec" in eng_m_code and
      "atomic_load_explicit(&g_scanBudgetSec" in eng_m_code)

# every SCAN_BUDGET_SEC() read in the engine: the walk guards are what makes a
# long run end instead of being killed
reads = re.findall(r"SCAN_BUDGET_SEC\(\)", eng_m_code)
check("BUG.3: the value is read at every guard site (>= 6 reads incl. the walks)",
      len(reads) >= 6, "%d read(s) of SCAN_BUDGET_SEC()" % len(reads))

# ---- BUG.4: a visible cancel, one path, no leak -----------------------------
check("BUG.4: the app has a tappable control with the word 'cancel'",
      "dotTapped:" in tvc and '@"cancel"' in tvc)
check("BUG.4: the label is visible only while a run is in flight",
      re.search(r"if \(state == 1\) \{\s*\n\s*self\.statusDot\.userInteractionEnabled = YES;", tvc)
      is not None and "self.cancelLabel.alpha = 0.0;" in tvc)
check("BUG.4: the tap reaches the engine's stop flag through the one bridge",
      "term_bridge_cancel()" in tvc and "kexploit_request_stop()" in bridge)
check("BUG.4: the control has an accessible name for VoiceOver",
      'accessibilityLabel = @"cancel"' in tvc)
check("BUG.4: the cancel exit is -7 and the app stops instead of retrying",
      "-7" in bridge and "cancel" in bridge.lower())
check("BUG.4: the engine honours the stop inside the spray and both walks",
      eng_m.count("kexploit_stop_requested()") >= 5,
      "%d stop-flag check(s) in the engine" % eng_m.count("kexploit_stop_requested()"))

# ---- BUG.5: the claim is replaced by a measurement ---------------------------
kc = read(ROOT / "kexploit/kwrite_counter.c")
check("BUG.5: one write primitive counts, both outcomes",
      "kwrite_count_emit" in kc and "kwrite_count_reset" in kc and
      "kwrite_count_emit(kwrite_src_current(), EARLY_KRW_LENGTH);" in eng_m_code)
check("BUG.5: the counters reset per attempt",
      eng_m_code.count("kwrite_count_reset();") >= 2,
      "%d reset site(s)" % eng_m_code.count("kwrite_count_reset();"))
check("BUG.5: the engine prints the measured total on a run exit",
      "kexploit_scan_writes()" in eng_m_code and "kexploit_scan_write_bytes()" in eng_m_code)
check("BUG.5: the app logs the measured number",
      "kexploit_scan_writes()" in bridge and "kexploit_scan_write_bytes()" in bridge
      and "kexploit_scan_write_failures()" in bridge)
check("BUG.5: the app's readonly row does NOT claim 'zero writes'",
      "no kernel writes" in settings_code and "zero writes" not in settings_code
      and "zero kernel writes" not in settings_code)

# the shipped strings of the actual artifact: the claim must be gone from the UI
check("BUG.5: the linked binary carries 0 'zero writes' / 'zero kernel writes'",
      raw.count(b"zero writes") == 0 and raw.count(b"zero kernel writes") == 0,
      "zero writes=%d zero kernel writes=%d no kernel writes=%d" %
      (raw.count(b"zero writes"), raw.count(b"zero kernel writes"),
       raw.count(b"no kernel writes")))
check("BUG.5: the binary carries the measured-writes line",
      b"engine-counted" in raw and b"write(s) /" in raw)

# ---- the engine half of BUG.3/4/5 inside the artifact ------------------------
for sym in (b"_kexploit_set_scan_budget", b"_kexploit_scan_budget",
            b"_kexploit_scan_writes", b"_kexploit_scan_write_bytes",
            b"_kexploit_scan_write_failures", b"_kexploit_request_stop",
            b"_kexploit_stop_requested", b"_kwrite_count_emit"):
    check("linked binary defines %s" % sym.decode(), sym in raw)

print()
print("invariant checks: %d ok, %d failed" % (ok, fail))
sys.exit(1 if fail else 0)
