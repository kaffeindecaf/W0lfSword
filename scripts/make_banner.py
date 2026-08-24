#!/usr/bin/env python3
"""Generate W0lfSword OG banner (1280x640) from the repo's ASCII wolf."""
from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
BG = (13, 17, 23)          # GitHub dark
WOLF = (147, 197, 253)     # light blue
TITLE = (255, 255, 255)
SUB = (139, 148, 158)      # GitHub muted gray
ACCENT = (56, 139, 253)    # GitHub blue

wolf = (
    "                         .d$$b\n"
    "                       .' TO$;\\\n"
    "                      /  : TP._;\n"
    "                     / _.;  :Tb|\n"
    "                    /   /   ;j$j\n"
    "                _.-\"       d$$$$\n"
    "              .' ..       d$$$$;\n"
    "             /  /P'      d$$$$P. |\\\n"
    "            /   \"      .d$$$P' |\\^\"l\n"
    "          .'           `T$P^\"\"\"\"\"  :\n"
    "      ._.'      _.'                ;\n"
    "   `-.-\".-'-' ._.       _.-\"    .-\"\n"
    " `.-\" _____  ._              .-\"\n"
    "-.(g$$$$$$$b.              .'\n"
    "  \"\"^^T$$$P^)            .(:\n"
    "    _/  -\"  /.'         /:/;\n"
    " ._.'-'`-'  \")/         /;/;\n"
    "`-.-\"..--\"\"   \" /         /  ;\n"
    ".- \" ..--\"\"        -'          :\n"
    "..--\"\"--.-\"         (\\      .-(\\\n"
    "  ..--\"\"              `-\\(\\/;`\n"
    "    _.                      :\n"
    "                            ;`-\n"
    "                           :\\\n"
    "                           ;\n"
)

def font(size, bold=False):
    for name in ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf",
                 "DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf"):
        try:
            return ImageFont.truetype(f"/usr/share/fonts/truetype/dejavu/{name}", size)
        except Exception:
            continue
    return ImageFont.load_default()

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

# subtle gradient band at top
for y in range(6):
    shade = (13 + y, 17 + y, 23 + y)
    d.rectangle([0, y, W, y], fill=shade)

# wolf on the right side
f = font(18, bold=False)
lines = wolf.split("\n")
# right-align: compute max width, place block ending at x=W-60
max_w = max(f.getbbox(l)[2] for l in lines)
x0 = W - 60 - max_w
y0 = 40
for l in lines:
    d.text((x0, y0), l, font=f, fill=WOLF)
    y0 += 19

# title + tagline on the left
tf = font(64, bold=True)
d.text((60, 150), "W0lfSword", font=tf, fill=TITLE)

sf = font(26)
d.text((64, 260), "iOS kernel exploit toolkit", font=sf, fill=SUB)
d.text((64, 300), "DarkSword R/W  ·  SSV Bypass  ·  XPF offset verification", font=sf, fill=ACCENT)

# status strip bottom-left
cf = font(20)
d.text((64, 560), "iOS 17 - 26  ·  A13/A15/A18  ·  USB deploy  ·  no device needed for offset research",
       font=cf, fill=SUB)

img.save("docs/og-banner.png")
print("saved docs/og-banner.png", img.size)
