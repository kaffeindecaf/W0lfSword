#!/usr/bin/env python3
"""Generate a terminal-style demo shot (docs/demo.png) from real session output.

The lines are genuine output captured during device testing (2026-08-24):
usbtest on the iPhone 14, XPF resolution, and the adderall Phase 6 flow.
"""
from PIL import Image, ImageDraw, ImageFont

W, H = 1000, 660
BG = (15, 17, 26)          # terminal dark
FG = (201, 209, 217)       # light gray
GREEN = (63, 185, 80)
BLUE = (88, 166, 255)
YELLOW = (210, 153, 34)
RED = (248, 81, 73)
GREY = (110, 118, 129)
ACCENT = (56, 139, 253)

lines = [
    ("$", BLUE, " ./W0lfSword usbtest"),
    ("", FG, ""),
    ("  \u2713", GREEN, " usbmuxd is running"),
    ("  \u2713", GREEN, " Device visible on USB: iPhone 14 (A15/t8110, iOS 26.0.1)"),
    ("  \u2713", GREEN, " Pairing valid - this computer is trusted"),
    ("  \u2713", GREEN, " Lockdown diagnostics round-trip OK (read-only)"),
    ("  \u2713", GREEN, " USB cable looks good (10/10 reads)"),
    ("", FG, ""),
    ("$", BLUE, " ./W0lfSword kernelcache resolve 26.0.1"),
    ("", FG, ""),
    ("  # kernel: xnu-12377.2.9~1/RELEASE_ARM64_T8030", GREY, ""),
    ("  0x0000000000000310 <- kernelStruct.task.itk_space", FG, ""),
    ("  0x0000000000000040 <- kernelStruct.vm_map.pmap", FG, ""),
    ("  0x0000000000000748 <- kernelStruct.proc.struct_size", FG, ""),
    ("", FG, ""),
    ("$", BLUE, " sudo ./W0lfSword adderall"),
    ("", FG, ""),
    ("  \u2713", GREEN, " USB SSH tunnel up - deploys go over USB"),
    ("  \u2713", GREEN, " SSH key installed on the phone (one-time)"),
    ("  \u2713", GREEN, " Target: com.tigisoftware.Filza (detected on phone)"),
    ("  Exploit: pe_v1   Retries: 5   SSV: yes", YELLOW, ""),
    ("", FG, ""),
    ("  \u2713", GREEN, " Built W0lfSword.dylib (1.2 MB)"),
    ("  \u2713", GREEN, " Deployed + Filza restarted"),
    ("  \u2713", GREEN, " Kernel R/W verified - sandbox escaped"),
    ("", FG, ""),
    ("  next:", GREY, " crash_monitor armed - device healthy, no panics"),
]

def font(size, bold=False):
    name = "DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf"
    try:
        return ImageFont.truetype(f"/usr/share/fonts/truetype/dejavu/{name}", size)
    except Exception:
        return ImageFont.load_default()

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

# title bar
d.rectangle([0, 0, W, 34], fill=(30, 34, 48))
for i, c in enumerate([(255,95,86), (255,189,46), (39,201,63)]):
    d.ellipse([14 + i*26, 11, 26 + i*26, 23], fill=c)
d.text((W//2 - 120, 9), "w0lfsword - test run (2026-08-24)", font=font(15), fill=GREY)

y = 52
for mark, color, rest in lines:
    if not mark and not rest:
        y += 12
        continue
    if mark == "$":
        d.text((24, y), "$", font=font(17, bold=True), fill=GREEN)
        d.text((44, y), rest, font=font(17, bold=True), fill=FG)
    elif mark == "  \u2713":
        d.text((24, y), mark, font=font(17), fill=GREEN)
        d.text((52, y), rest, font=font(17), fill=FG)
    else:
        d.text((24, y), (mark + rest), font=font(17), fill=color)
    y += 24

img.save("docs/demo.png")
print("saved docs/demo.png", img.size)
