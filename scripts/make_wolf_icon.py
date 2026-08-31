#!/usr/bin/env python3
# make_wolf_icon.py - renders the W0lfSword arctic-wolf ASCII art as the
# Filza app icon, all sizes, dark navy + ice-blue theme.
import os, random
from PIL import Image, ImageDraw, ImageFont

ART = [l.rstrip("\n") for l in open("scripts/wolf_art.txt").read().splitlines() if l.strip() != ""]

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
if not os.path.exists(FONT):
    for cand in ["/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
                 "/usr/share/fonts/TTF/DejaVuSansMono.ttf"]:
        if os.path.exists(cand):
            FONT = cand
            break

W, H = 1024, 1024
art_w = max(len(l) for l in ART)
fs = int((W * 0.80) / (art_w * 0.602))
font = ImageFont.truetype(FONT, fs)

# --- background: vertical navy gradient + subtle vignette ---
top = (10, 16, 32)      # #0A1020
bot = (22, 30, 52)      # #161E34
img = Image.new("RGB", (W, H))
px = img.load()
for y in range(H):
    t = y / (H - 1)
    r = int(top[0] + (bot[0] - top[0]) * t)
    g = int(top[1] + (bot[1] - top[1]) * t)
    b = int(top[2] + (bot[2] - top[2]) * t)
    for x in range(W):
        px[x, y] = (r, g, b)

d = ImageDraw.Draw(img, "RGBA")

# --- sparse snow specks (seeded for reproducibility) ---
rng = random.Random(0xC0FFEE)
for _ in range(140):
    x, y = rng.randrange(W), rng.randrange(H)
    rad = rng.choice([2, 2, 3, 4])
    a = rng.randrange(30, 90)
    d.ellipse([x - rad, y - rad, x + rad, y + rad], fill=(190, 220, 255, a))

# --- soft glow pass behind the wolf ---
glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
gd = ImageDraw.Draw(glow)
line_h = fs * 1.45
total_h = line_h * len(ART)
y0 = (H - total_h) / 2
for i, line in enumerate(ART):
    lw = gd.textlength(line, font=font)
    gd.text(((W - lw) / 2, y0 + i * line_h), line, font=font, fill=(120, 180, 255, 46))
img = Image.alpha_composite(img.convert("RGBA"), glow).convert("RGB")

# --- the wolf itself ---
d = ImageDraw.Draw(img, "RGBA")
wolf = (168, 216, 255)      # ice blue
for i, line in enumerate(ART):
    lw = d.textlength(line, font=font)
    d.text(((W - lw) / 2, y0 + i * line_h), line, font=font, fill=wolf)

# --- subtle border (looks sharp on any wallpaper) ---
d.rectangle([0, 0, W - 1, H - 1], outline=(90, 130, 190, 255), width=6)

OUT = ".theos/icon_out"
os.makedirs(OUT, exist_ok=True)

SIZES = {
    "AppIcon29x29.png": 29,
    "AppIcon29x29@2x.png": 58,
    "AppIcon29x29@3x.png": 87,
    "AppIcon29x29~ipad.png": 29,
    "AppIcon29x29@2x~ipad.png": 58,
    "AppIcon40x40.png": 40,
    "AppIcon40x40@2x.png": 80,
    "AppIcon40x40@3x.png": 120,
    "AppIcon40x40~ipad.png": 40,
    "AppIcon40x40@2x~ipad.png": 80,
    "AppIcon60x60@2x.png": 120,
    "AppIcon60x60@3x.png": 180,
    "AppIcon76x76~ipad.png": 76,
    "AppIcon76x76@2x~ipad.png": 152,
    "AppIcon83.5x83.5@2x~ipad.png": 167,
}
for name, size in SIZES.items():
    img.resize((size, size), Image.LANCZOS).save(os.path.join(OUT, name))
    print(f"{name}: {size}x{size}")

print("master: 1024x1024")
