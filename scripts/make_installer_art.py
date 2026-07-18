"""Generate WiX installer bitmaps from the Mischief logo.

Outputs two BMPs (the exact sizes the WixUI dialog set expects) into
installer/ so they can be committed and used by CI without the brand logo
(which lives outside the repo):

  installer/banner.bmp  493x58   - top strip on interior dialogs. WiX draws the
                                    dialog TITLE in dark ink on the LEFT, so that
                                    area stays white; the mark sits on the right.
  installer/dialog.bmp  493x312  - Welcome/Exit background. WiX draws the title +
                                    body in dark ink on the RIGHT ~2/3, so that
                                    stays white; the left 164px is a navy brand
                                    panel with the mark.

The key constraint: WiX renders its text in a fixed dark color, so wherever
text lands the bitmap must be light. A fully-dark bitmap makes the text
invisible (which is exactly what a naive navy fill did).

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
PANEL_W = 164            # WiX left art column on the dialog bitmap
WHITE = (255, 255, 255)


def navy(logo):
    """The logo's dark field color, sampled from a corner."""
    return logo.convert("RGB").getpixel((4, 4))


def extract_glyph(logo):
    """Return the orange mark cropped to its bounds as RGBA with a soft alpha.

    The logo is a bright-orange glyph on a dark field; alpha is derived from
    the red channel (near-zero on the navy background and its faint grid,
    ~full on the orange), giving clean anti-aliased edges that composite onto
    any background color.
    """
    rgb = logo.convert("RGB")
    W, H = rgb.size
    px = rgb.load()
    lo, hi = 45, 235  # red-channel range mapped to alpha 0..255
    out = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    op = out.load()
    xs, ys = [], []
    for y in range(H):
        for x in range(W):
            r, g, b = px[x, y]
            a = 0 if r <= lo else (255 if r >= hi else int((r - lo) * 255 / (hi - lo)))
            if a and r > b:  # orange, not a bluish grid line
                op[x, y] = (r, g, b, a)
                xs.append(x)
                ys.append(y)
    return out.crop((min(xs), min(ys), max(xs) + 1, max(ys) + 1))


def fit(img, box_w, box_h):
    r = min(box_w / img.width, box_h / img.height)
    return img.resize((max(1, int(img.width * r)), max(1, int(img.height * r))), Image.LANCZOS)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SRC
    os.makedirs(OUT_DIR, exist_ok=True)
    logo = Image.open(src).convert("RGBA")
    fill = navy(logo)
    glyph = extract_glyph(logo)

    # Banner: white field (dark title text stays readable), orange mark at right.
    banner = Image.new("RGB", BANNER, WHITE)
    g = fit(glyph, 46, 46)
    banner.paste(g, (BANNER[0] - g.width - 12, (BANNER[1] - g.height) // 2), g)
    banner.save(os.path.join(OUT_DIR, "banner.bmp"))

    # Dialog: navy brand panel on the left, white on the right for the text.
    dialog = Image.new("RGB", DIALOG, WHITE)
    dialog.paste(Image.new("RGB", (PANEL_W, DIALOG[1]), fill), (0, 0))
    # Thin orange rule separating panel from text area.
    dialog.paste(Image.new("RGB", (2, DIALOG[1]), (245, 130, 31)), (PANEL_W, 0))
    g = fit(glyph, 128, 128)
    dialog.paste(g, ((PANEL_W - g.width) // 2, (DIALOG[1] - g.height) // 2), g)
    dialog.save(os.path.join(OUT_DIR, "dialog.bmp"))

    print(f"Wrote banner.bmp {BANNER} and dialog.bmp {DIALOG} to {OUT_DIR} "
          f"(panel {fill}, text area white)")


if __name__ == "__main__":
    main()
