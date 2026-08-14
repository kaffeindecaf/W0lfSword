"""Arctic Wolf color palette — shared across all usbliter8-arctic modules."""

class C:
    WOLF  = '\033[38;5;153m'
    ICE   = '\033[38;5;195m'
    FROST = '\033[38;5;117m'
    SNOW  = '\033[38;5;255m'
    GREY  = '\033[38;5;245m'
    DIM   = '\033[38;5;240m'
    STEEL = '\033[38;5;109m'
    MOON  = '\033[38;5;188m'
    EYE   = '\033[1;38;5;39m'
    RED   = '\033[0;31m'
    GRN   = '\033[0;32m'
    AMB   = '\033[1;33m'
    NC    = '\033[0m'
    B     = '\033[1m'
    D     = '\033[2m'


def ok(msg: str) -> str:
    return f"  {C.GRN}✓{C.NC} {msg}"

def err(msg: str) -> str:
    return f"  {C.RED}✗{C.NC} {msg}"

def warn(msg: str) -> str:
    return f"  {C.AMB}⚠{C.NC} {msg}"

def info(msg: str) -> str:
    return f"  {C.ICE}ℹ{C.NC} {msg}"

def stage(n: int, msg: str) -> str:
    return f"  {C.EYE}[{n}]{C.NC} {msg}"

def header(text: str) -> str:
    bar = "═" * 56
    return (f"\n  {C.DIM}╔{bar}╗{C.NC}\n"
            f"  {C.DIM}║{C.NC}  {C.SNOW}{C.B}{text:^52}{C.NC}  {C.DIM}║{C.NC}\n"
            f"  {C.DIM}╚{bar}╝{C.NC}")

def section(text: str) -> str:
    return f"\n  {C.FROST}{C.B}{text}{C.NC}\n  {C.DIM}{'─' * len(text)}{C.NC}"

def key_value(key: str, value: str) -> str:
    return f"  {C.GREY}{key:<14}{C.NC} {value}"

def prompt(text: str) -> str:
    return f"  {C.FROST}{text}{C.NC} "

def divider() -> str:
    return f"  {C.DIM}{'─' * 56}{C.NC}"

def progress_bar(current: int, total: int, width: int = 20) -> str:
    pct = (current * 100) // total if total > 0 else 0
    filled = (pct * width) // 100
    empty = width - filled
    return f"{C.GRN}{'▓' * filled}{C.DIM}{'░' * empty}{C.NC} {pct}%"
