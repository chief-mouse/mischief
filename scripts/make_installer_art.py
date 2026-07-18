"""Generate WiX installer bitmaps from the Mischief logo.

Outputs two BMPs (the exact sizes the WixUI dialog set expects) into
installer/ so they can be committed and used by CI without the brand logo
(which lives outside the repo):

  installer/banner.bmp  493x58   - top strip on most dialogs; art sits on the
                                    right, WiX draws the dialog title on the left
  installer/dialog.bmp  493x312  - Welcome/Complete background; art sits in the
                                    left ~164px column, WiX draws text on the right

Usage: python scripts/make_installer_art.py [path-to-logo.png]
"""
import os
import sys
from PIL import Image

DEFAULT_SRC = (r"C:\Users\admin\OneDrive - mischief.dev\Documents"
               r"\Agency_Operations\mischief-dev-logo-final-400.png")
PROJ_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT_DIR = os.path.join(PROJ_DIR, "installer")

BANNER = (493, 58)
DIALOG = (493, 312)


def bg_color(img):
    """Sample the logo's corner as the fill color (its dark navy field)."""
    return img.convert("RGB").getpixel((4, 4))


def glyph_bbox(img):
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


def tight_glyph(logo):
    x0, y0, x1, y1 = glyph_bbox(logo)
    pad = int(max(x1 - x0, y1 - y0) * 0.12)
    W, H = logo.size
    return logo.crop((max(0, x0 - pad), max(0, y0 - pad),
                      min(W, x1 + pad), min(H, y1 + pad)))


def fit(img, box_w, box_h):
    """Scale img to fit within (box_w, box_h), preserving aspect."""
    r = min(box_w / img.width, box_h / img.height)
    return img.resize((max(1, int(img.width * r)), max(1, int(img.height * r))), Image.LANCZOS)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SRC
    os.makedirs(OUT_DIR, exist_ok=True)
    logo = Image.open(src).convert("RGBA")
    fill = bg_color(logo)
    glyph = tight_glyph(logo)

    # Banner: mark on the right, matching WiX's art region; leave the left clear
    # for the dialog title WiX renders over this bitmap.
    banner = Image.new("RGB", BANNER, fill)
    g = fit(glyph, 52, 52)
    banner.paste(g, (BANNER[0] - g.width - 10, (BANNER[1] - g.height) // 2),
                 g if g.mode == "RGBA" else None)
    banner.save(os.path.join(OUT_DIR, "banner.bmp"))

    # Dialog: mark centered in the left ~164px art column.
    dialog = Image.new("RGB", DIALOG, fill)
    g = fit(glyph, 150, 150)
    dialog.paste(g, ((164 - g.width) // 2, (DIALOG[1] - g.height) // 2),
                 g if g.mode == "RGBA" else None)
    dialog.save(os.path.join(OUT_DIR, "dialog.bmp"))

    print(f"Wrote banner.bmp {BANNER} and dialog.bmp {DIALOG} to {OUT_DIR} (fill {fill})")


if __name__ == "__main__":
    main()
