import sys
p = "/home/kaffein/.hermes/skills/software-development/w0lfsword-development/SKILL.md"
s = open(p).read()
old = "- **ObjC labels in `llvm-objdump --disassemble` end in `]>:`, not `]:`** (`+[C sel:]>:`, `+` class / `-` instance), so `grep -F -- \"-[C sel:]:\"` silently matches nothing. Confirm the grep form on a label you can see before trusting an empty result. And read a built binary only after `scripts/check_host_verification.sh --with-builds` rebuilt and re-hashed it (a matching pinned `app_binary` sha is what makes the evidence about this tree, not a stale artifact)."
new = ("- **ObjC labels in `llvm-objdump --disassemble` end in `]>:`**; `-d --macho --no-show-raw-insn` writes plain `<name>:` instead (parse both, treat `^[0-9a-f]{6,}:` as an instruction). Read a binary only after `check_host_verification.sh --with-builds` rebuilt/re-hashed it.\n"
       "- **A grep for old wording hits the bug history too**: comments quote pre-fix text verbatim (a stale `#define EXPLOIT_SCAN_BUDGET_SEC 120`, `\"zero kernel writes\"`), so strip `//`-comments before asserting on source, and assert on the built binary's strings as well.")
print("in file:", old in s)
print("current:", len(s), "delta:", len(new) - len(old), "total:", len(s) + len(new) - len(old))
