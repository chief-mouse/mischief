"""Regenerate src/mschf/resources/mschf.{png,ico} from the Mischief brand logo.

Usage: python scripts/make_icons.py [path-to-logo.png]

Defaults to the logo in the Agency_Operations OneDrive folder. The .ico embeds
16-256px frames; sizes <=64px are cropped tight around the orange glyph before
downscaling so the mark stays legible in title bars and the taskbar, while
large sizes keep the full framed logo.
"""
import os
import sys
from PIL import Image

DEFAULT_SRC = (r"C:\Users\admin\OneDrive - mischief.dev\Documents"
               r"\Agency_Operations\mischief-dev-logo-final-400.png")
PROJ_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEST_DIR = os.path.join(PROJ_DIR, "src", "mschf", "resources")


def glyph_bbox(img):
    """Bounding box of the orange glyph (dominant red, low blue)."""
    px = img.load()
    W, H = img.size
    xs, ys = [], []
    for y in range(0, H, 2):
        for x in range(0, W, 2):
            r, g, b, a = px[x, y]
            if a > 100 and r > 150 and b < 110 and r > b + 80:
                xs.append(x)
                ys.append(y)
    return min(xs), min(ys), max(xs), max(ys)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SRC
    os.makedirs(DEST_DIR, exist_ok=True)
    logo = Image.open(src).convert("RGBA")
    W, H = logo.size

    x0, y0, x1, y1 = glyph_bbox(logo)
    side = min(int(max(x1 - x0, y1 - y0) * 1.24), W, H)
    cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
    left = max(0, min(W - side, cx - side // 2))
    top = max(0, min(H - side, cy - side // 2))
    tight = logo.crop((left, top, left + side, top + side))

    logo.save(os.path.join(DEST_DIR, "mschf.png"))

    frames = []
    for s in (16, 24, 32, 48, 64, 128, 256):
        frames.append((tight if s <= 64 else logo).resize((s, s), Image.LANCZOS))
    frames[-1].save(os.path.join(DEST_DIR, "mschf.ico"),
                    append_images=frames[:-1], sizes=[f.size for f in frames])
    print(f"Wrote mschf.png and mschf.ico ({len(frames)} frames) to {DEST_DIR}")


if __name__ == "__main__":
    main()
