"""Generates the toolDHCP logo and icons into assets/ (needs Pillow, build-time only).

Glyph: a hexagon (the 'node') with a star topology inside: a hub and three
endpoints. Blue -> cyan gradient on near-black.

Usage: python tools/make_icons.py
Outputs: assets/icon.ico (16..256), assets/icon.png (512), assets/logo.png (256, transparent)
"""
import math
import os

from PIL import Image, ImageChops, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "assets")
S = 1024                       # master size, downscaled with LANCZOS
BG = (9, 13, 22, 255)
TOP, BOTTOM = (34, 211, 238), (37, 99, 235)   # cyan -> electric blue


def gradient(size):
    g = Image.new("RGBA", (size, size))
    px = g.load()
    for y in range(size):
        t = y / (size - 1)
        c = tuple(int(TOP[i] * (1 - t) + BOTTOM[i] * t) for i in range(3)) + (255,)
        for x in range(size):
            px[x, y] = c
    return g


def glyph_mask(size, scale=1.0):
    """White shapes on black (L mode): hexagon outline, 3 links, hub, 3 endpoints."""
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    cx = cy = size / 2
    R = size * 0.40 * scale
    hexp = [(cx + R * math.cos(math.radians(60 * k - 90)), cy + R * math.sin(math.radians(60 * k - 90)))
            for k in range(6)]
    d.line(hexp + [hexp[0]], fill=255, width=int(size * 0.045), joint="curve")
    for p in hexp:
        d.ellipse([p[0] - size * 0.0225, p[1] - size * 0.0225, p[0] + size * 0.0225, p[1] + size * 0.0225], fill=255)
    r_end = R * 0.56
    ends = [(cx + r_end * math.cos(math.radians(a)), cy + r_end * math.sin(math.radians(a)))
            for a in (-90, 30, 150)]
    for e in ends:
        d.line([(cx, cy), e], fill=255, width=int(size * 0.035))
    hub = size * 0.075 * scale
    d.ellipse([cx - hub, cy - hub, cx + hub, cy + hub], fill=255)
    for e in ends:
        r = size * 0.055 * scale
        d.ellipse([e[0] - r, e[1] - r, e[0] + r, e[1] + r], fill=255)
    return m


def glyph(size, scale=1.0):
    g = gradient(size)
    g.putalpha(glyph_mask(size, scale))
    return g


def icon_master():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=int(S * 0.22), fill=255)
    bg = Image.new("RGBA", (S, S), BG)
    img.paste(bg, (0, 0), mask)
    # subtle inner glow ring
    ring = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(ring).rounded_rectangle([14, 14, S - 15, S - 15], radius=int(S * 0.21),
                                           outline=(37, 99, 235, 90), width=6)
    img = Image.alpha_composite(img, ring)
    return Image.alpha_composite(img, glyph(S, 0.92))


def main():
    os.makedirs(OUT, exist_ok=True)
    master = icon_master()
    master.resize((512, 512), Image.LANCZOS).save(os.path.join(OUT, "icon.png"))
    master.save(os.path.join(OUT, "icon.ico"),
                sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    glyph(S, 1.0).resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, "logo.png"))
    print("written to", os.path.normpath(OUT))


if __name__ == "__main__":
    main()
