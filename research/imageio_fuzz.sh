#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  imageio_fuzz.sh — K4.2 ImageIO fuzzing harness
#
#  Mutates DNG/HEIF/TIFF seeds, pushes samples to the phone, opens them
#  through QuickLook/Filza (ImageIO decode), collects crash reports, and
#  flags unique panic signatures.
#
#  Tools:  research/imageio_mutate.py  (deterministic mutator + manifest)
#          referenceforAI/projects/CVE-2025-43300-hunters/ (seed corpus,
#          hex_modifier.py, dng_vulnerability_analyzer.py)
#
#  Usage:  research/imageio_fuzz.sh <command> [options]
#    prepare   — generate mutated corpus into .w0lfsword/fuzz/corpus/
#    list      — corpus + manifest summary
#    push      — scp the corpus to the phone
#    run       — open each sample on the phone, attribute crashes
#    collect   — pull FilzaTweak.log + CrashReporter .ips to results/
#    report    — dedupe crash signatures, flag unique panics
#    (no args) — prepare → push → run → collect → report
#
#  Options: --device <ip>  --count <N>  --strategy dng|generic|all
#           --seeds <dir>  --wait <sec>  --yes
# ═══════════════════════════════════════════════════════════════════
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

HUNTERS="$PROJECT_DIR/referenceforAI/projects/CVE-2025-43300-hunters"
MUTATOR="$PROJECT_DIR/research/imageio_mutate.py"
FUZZ_DIR="$PROJECT_DIR/.w0lfsword/fuzz"
CORPUS="$FUZZ_DIR/corpus"
RESULTS="$FUZZ_DIR/results"
MANIFEST="$FUZZ_DIR/manifest.tsv"
MAPFILE="$FUZZ_DIR/sample_crashes.tsv"     # sample → crash report attribution
SIGFILE="$FUZZ_DIR/signatures.tsv"         # deduped crash signatures
DEVICE_DIR="/var/mobile/Documents/.fuzz_corpus"

C_FROST='\033[38;5;117m'; C_GRN='\033[0;32m'; C_AMB='\033[1;33m'
C_RED='\033[0;31m'; C_DIM='\033[38;5;240m'; C_EYE='\033[1;38;5;39m'; NC='\033[0m'
ok()   { printf "  ${C_GRN}✓${NC} %s\n" "$1"; }
err()  { printf "  ${C_RED}✗${NC} %s\n" "$1"; }
warn() { printf "  ${C_AMB}⚠${NC} %s\n" "$1"; }
stage(){ printf "  ${C_EYE}[%s]${NC} %s\n" "$1" "$2"; }
hint() { printf "  ${C_DIM}  → %s${NC}\n" "$1"; }

ssh_safe() {
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
        -o ServerAliveInterval=5 -o ServerAliveCountMax=2 "$@" 2>/dev/null
}
scp_safe() {
    scp -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
        "$@" 2>/dev/null
}

DEVICE=""; COUNT=24; STRATEGY="all"; SEEDS="$HUNTERS/dng_images"; WAIT=4; YES_MODE=false

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --device) DEVICE="${2:-}"; shift 2;;
            --count)  COUNT="${2:-24}"; shift 2;;
            --strategy) STRATEGY="${2:-all}"; shift 2;;
            --seeds)  SEEDS="${2:-}"; shift 2;;
            --wait)   WAIT="${2:-4}"; shift 2;;
            --yes)    YES_MODE=true; shift;;
            *) echo "  ${C_RED}unknown option: $1${NC}" >&2; return 1;;
        esac
    done
}

confirm() {
    $YES_MODE && return 0
    local msg="${1:-Continue?}"
    printf "  ${C_AMB}${msg} [y/N]${NC} "; read -r ans
    [ "$ans" = "y" ] || [ "$ans" = "Y" ]
}

get_device() {
    [ -n "$DEVICE" ] && echo "$DEVICE" && return 0
    [ -f "$PROJECT_DIR/.w0lfsword/active_device" ] && cat "$PROJECT_DIR/.w0lfsword/active_device" && return 0
    echo ""
}

require_device() {
    local ip; ip=$(get_device)
    if [ -z "$ip" ]; then
        err "No device — pass --device <ip> or use 'device add'"
        return 1
    fi
    if ! ssh_safe "root@$ip" "echo ok" 2>/dev/null | grep -q ok; then
        err "SSH failed to root@$ip — device offline or OpenSSH not installed"
        return 1
    fi
    echo "$ip"
}

# ── prepare ────────────────────────────────────────────────────────
cmd_prepare() {
    stage "corpus" "generating mutations into $CORPUS"
    mkdir -p "$CORPUS"
    rm -f "$MANIFEST"
    local seeds=()
    if [ -d "$SEEDS" ]; then
        for f in "$SEEDS"/*; do
            [ -f "$f" ] && case "$f" in
                *.DNG|*.dng|*.HEIF|*.heif|*.HEIC|*.heic|*.TIF|*.tif|*.TIFF|*.tiff|*.jpg|*.jpeg|*.exr) seeds+=("$f");;
            esac
        done
    elif [ -n "$SEEDS" ] && [ -f "$SEEDS" ]; then
        seeds+=("$SEEDS")
    fi
    if [ ${#seeds[@]} -eq 0 ]; then
        err "No seed files found in $SEEDS"
        hint "Drop DNG/HEIF/TIFF files in a dir and pass --seeds <dir>, or point at the hunters corpus."
        return 1
    fi
    ok "${#seeds[@]} seed(s): $(basename "${seeds[0]}")${seeds[1]:+ …}"
    local total=0
    for s in "${seeds[@]}"; do
        python3 "$MUTATOR" "$s" "$CORPUS" --count "$COUNT" --strategy "$STRATEGY" --manifest "$MANIFEST" >/dev/null || { warn "mutator failed on $s"; continue; }
        total=$((total + 1))
    done
    local n; n=$(wc -l < "$MANIFEST" 2>/dev/null || echo 0)
    ok "$n mutated samples from $total seed(s) — manifest: $MANIFEST"
    hint "Open/verify a sample: dng_vulnerability_analyzer.py <corpus file>"
}

# ── list ───────────────────────────────────────────────────────────
cmd_list() {
    if [ ! -f "$MANIFEST" ]; then
        err "No manifest yet — run: research/imageio_fuzz.sh prepare"
        return 1
    fi
    echo ""
    printf "  ${C_FROST}%-40s${NC} %-8s %s\n" "sample" "strategy" "mutation"
    printf "  ${C_DIM}%s${NC}\n" "$(printf '─%.0s' {1..78})"
    awk -F'\t' '{ printf "  \033[38;5;117m%-40s\033[0m %-8s %s\n", $2, $3, $7 }' "$MANIFEST"
    echo ""
    printf "  ${C_DIM}%s samples · corpus: %s${NC}\n" "$(wc -l < "$MANIFEST")" "$CORPUS"
}

# ── push ───────────────────────────────────────────────────────────
cmd_push() {
    local ip; ip=$(require_device) || return 1
    [ -f "$MANIFEST" ] || { err "No corpus yet — run prepare first"; return 1; }
    local n; n=$(wc -l < "$MANIFEST")
    confirm "Upload $n samples to root@$ip:$DEVICE_DIR ?" || { err "Aborted"; return 1; }
    stage "push" "clearing $DEVICE_DIR on device"
    ssh_safe "root@$ip" "rm -rf '$DEVICE_DIR' && mkdir -p '$DEVICE_DIR' && chown mobile:mobile '$DEVICE_DIR'" || true
    stage "push" "uploading $n samples (scp, retried)"
    local i=0
    while IFS= read -r fname; do
        i=$((i + 1))
        scp_safe "$CORPUS/$fname" "root@$ip:$DEVICE_DIR/" 2>/dev/null || warn "scp failed: $fname"
        [ $((i % 10)) -eq 0 ] && printf "  ${C_DIM}… %d/%d${NC}\r" "$i" "$n"
    done < <(cut -f2 "$MANIFEST")
    printf "\r  \033[K"
    ssh_safe "root@$ip" "chown -R mobile:mobile '$DEVICE_DIR'" || true
    ok "pushed $n samples — device dir: $DEVICE_DIR (open them in Filza → Documents → .fuzz_corpus)"
}

# ── run ────────────────────────────────────────────────────────────
cmd_run() {
    local ip; ip=$(require_device) || return 1
    [ -f "$MANIFEST" ] || { err "No corpus yet — run prepare first"; return 1; }
    confirm "Open every sample on the phone via uiopen/QuickLook? (device survives; apps may crash)" || { err "Aborted"; return 1; }
    stage "run" "attributing crashes per sample (wait ${WAIT}s between opens)"
    rm -f "$MAPFILE"
    : > "$MAPFILE"
    local n=0 total; total=$(wc -l < "$MANIFEST")
    local has_uiopen; has_uiopen=$(ssh_safe "root@$ip" "command -v uiopen" 2>/dev/null || echo "")
    [ -z "$has_uiopen" ] && warn "uiopen not found on device — run 'push' then open samples manually in Filza"
    while IFS= read -r fname; do
        n=$((n + 1))
        printf "  ${C_DIM}%3d/%d ${C_EYE}%s${NC}" "$n" "$total" "$fname"
        if [ -z "$has_uiopen" ]; then
            echo ""
            continue
        fi
        # snapshot newest crash report before opening
        local before; before=$(ssh_safe "root@$ip" "ls -t /var/mobile/Library/Logs/CrashReporter/*.ips 2>/dev/null | head -1" 2>/dev/null || echo "")
        ssh_safe "root@$ip" "uiopen 'file://$DEVICE_DIR/$fname'" 2>/dev/null || true
        sleep "$WAIT"
        local after; after=$(ssh_safe "root@$ip" "ls -t /var/mobile/Library/Logs/CrashReporter/*.ips 2>/dev/null | head -1" 2>/dev/null || echo "")
        if [ -n "$after" ] && [ "$after" != "$before" ]; then
            echo -e "  ${C_RED}← CRASH${NC} $after"
            printf "%s\t%s\n" "$fname" "$after" >> "$MAPFILE"
        else
            echo -e "  ${C_DIM}ok${NC}"
        fi
    done < <(cut -f2 "$MANIFEST")
    ok "run complete — attributed crashes: $(wc -l < "$MAPFILE")"
    hint "Collect evidence: research/imageio_fuzz.sh collect"
}

# ── collect ────────────────────────────────────────────────────────
cmd_collect() {
    local ip; ip=$(require_device) || return 1
    mkdir -p "$RESULTS"
    stage "collect" "pulling /tmp/FilzaTweak.log"
    ssh_safe "root@$ip" "cat /tmp/FilzaTweak.log 2>/dev/null" > "$RESULTS/filza_tweak.log" 2>/dev/null || true
    local sz; sz=$(wc -c < "$RESULTS/filza_tweak.log" 2>/dev/null || echo 0)
    [ "$sz" -gt 0 ] && ok "FilzaTweak.log ($(du -h "$RESULTS/filza_tweak.log" | cut -f1))" || warn "FilzaTweak.log empty — tweak may not have run"
    stage "collect" "pulling recent CrashReporter .ips (last 120 min)"
    local n=0
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        local base; base=$(basename "$f")
        ssh_safe "root@$ip" "cat '$f'" > "$RESULTS/$base" 2>/dev/null && n=$((n + 1))
    done < <(ssh_safe "root@$ip" "find /var/mobile/Library/Logs/CrashReporter -name '*.ips' -mmin -120 2>/dev/null" 2>/dev/null || true)
    ok "$n crash report(s) pulled into $RESULTS"
}

# ── report ─────────────────────────────────────────────────────────
cmd_report() {
    [ -d "$RESULTS" ] || { err "No results yet — run collect first"; return 1; }
    stage "report" "deduping crash signatures"
    local n; n=$(ls "$RESULTS"/*.ips 2>/dev/null | wc -l | tr -d ' ')
    if [ "$n" -eq 0 ]; then
        warn "No .ips crash reports collected — no ImageIO crash triggered on this run"
        hint "26.5+ patched the known bugs; 26.1–26.4.x should crash on the CVE-2026-28990 EXR or DNG recipes."
        return 0
    fi
    ok "$n crash report(s)"
    python3 - "$RESULTS" "$MAPFILE" "$SIGFILE" <<'PYEOF'
import json, sys, os, glob
resdir, mapfile, sigfile = sys.argv[1], sys.argv[2], sys.argv[3]

def signature(path):
    try:
        with open(path) as f:
            d = json.load(f)
    except Exception:
        return None, "unparseable", path
    exc = d.get("exception", {})
    term = d.get("termination", {})
    proc = d.get("procName", "?")
    faulting = ""
    for th in d.get("threads", []):
        for fr in th.get("frames", []):
            if fr.get("symbol", "").startswith(("ImageIO", "RawCamera", "CoreMedia", "libJPEG", "AppleJPEG")):
                faulting = fr["symbol"].split(" ")[0]
                break
        if faulting: break
    reasons = term.get("reasons") or []
    reason = reasons[0] if reasons else ""
    sig = "|".join([proc, str(exc.get("type", "?")), str(exc.get("signal", "")), reason, faulting])
    return sig, reason, proc

seen = {}
for p in sorted(glob.glob(os.path.join(resdir, "*.ips"))):
    sig, reason, proc = signature(p)
    seen.setdefault(sig, []).append(os.path.basename(p))

rows = sorted(seen.items(), key=lambda kv: -len(kv[1]))
with open(sigfile, "w") as f:
    for sig, files in rows:
        f.write(f"{len(files)}\t{sig}\t{','.join(files)}\n")

print(f"  {len(rows)} unique signature(s):")
for i, (sig, files) in enumerate(rows):
    flag = "  \033[1;33m← UNIQUE\033[0m" if len(files) == 1 else ""
    print(f"    {i+1:2d}. [{len(files)}x] {sig}{flag}")
    print(f"         {files[0]}")

# correlate with the run map
if os.path.exists(mapfile) and os.path.getsize(mapfile) > 0:
    print("\n  Sample attribution:")
    for line in open(mapfile):
        sample, crash = line.rstrip().split("\t")
        print(f"    {sample}  →  {os.path.basename(crash)}")
PYEOF
    echo ""
    echo -e "  ${C_DIM}Signatures saved: $SIGFILE — unique ones (1x) are the interesting finds.${NC}"
}

usage() {
    printf "  ${C_FROST}imageio_fuzz.sh${NC} — K4.2 ImageIO fuzzing harness\n"
    echo ""
    printf "  ${C_DIM}Commands:${NC}\n"
    printf "    prepare   generate mutated corpus (DNG/HEIF/TIFF) + manifest\n"
    printf "    list      show corpus samples + mutation recipes\n"
    printf "    push      upload corpus to the phone\n"
    printf "    run       open samples on the phone, attribute crashes per sample\n"
    printf "    collect   pull FilzaTweak.log + CrashReporter .ips to results/\n"
    printf "    report    dedupe crash signatures, flag unique panics\n"
    printf "    (no args) prepare → push → run → collect → report\n"
    echo ""
    printf "  ${C_DIM}Options:${NC} --device <ip>  --count <N>  --strategy dng|jpeg|generic|all\n"
    printf "           --seeds <dir>  --wait <sec>  --yes\n"
    echo ""
    printf "  ${C_DIM}State:${NC}    .w0lfsword/fuzz/  (corpus, manifest, results, signatures)\n"
}

CMD="${1:-}"
[ "$CMD" = "--help" ] || [ "$CMD" = "-h" ] && { usage; exit 0; }
if [ "$CMD" = "prepare" ] || [ "$CMD" = "list" ] || [ "$CMD" = "push" ] ||
   [ "$CMD" = "run" ] || [ "$CMD" = "collect" ] || [ "$CMD" = "report" ]; then
    shift
else
    [ -n "$CMD" ] && { echo "  ${C_RED}unknown command: $CMD${NC}"; usage; exit 1; }
fi
parse_args "$@" || exit 1

case "$CMD" in
    prepare)  cmd_prepare;;
    list)     cmd_list;;
    push)     cmd_push;;
    run)      cmd_run;;
    collect)  cmd_collect;;
    report)   cmd_report;;
    "")       cmd_prepare && cmd_push && cmd_run && cmd_collect && cmd_report;;
esac
