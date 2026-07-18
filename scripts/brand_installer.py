"""Brand the generated WiX installer with the Mischief bitmaps.

`briefcase create windows app` regenerates the installer scaffold (a gitignored
build/ tree) from the cookiecutter template, which ships no banner art — so WiX
falls back to its red default. This script runs AFTER create and BEFORE build:
it copies installer/{banner,dialog}.bmp next to the generated .wxs and injects
the two WixVariables that point WiX at them. Idempotent.

Usage: python scripts/brand_installer.py [scaffold_dir]
       (default scaffold_dir: build/mschf/windows/app)
"""
import os
import shutil
import sys

PROJ_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
INSTALLER_DIR = os.path.join(PROJ_DIR, "installer")
DEFAULT_SCAFFOLD = os.path.join(PROJ_DIR, "build", "mschf", "windows", "app")

BITMAPS = {"banner.bmp": "WixUIBannerBmp", "dialog.bmp": "WixUIDialogBmp"}
ANCHOR = '<WixVariable Id="WixUILicenseRtf" Value="LICENSE.rtf" />'


def main():
    scaffold = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SCAFFOLD
    wxs_path = os.path.join(scaffold, "mschf.wxs")
    if not os.path.isfile(wxs_path):
        sys.exit(f"wxs not found at {wxs_path} — run `briefcase create windows app` first")

    for bmp in BITMAPS:
        src = os.path.join(INSTALLER_DIR, bmp)
        if not os.path.isfile(src):
            sys.exit(f"missing {src} — run scripts/make_installer_art.py")
        shutil.copy2(src, os.path.join(scaffold, bmp))

    with open(wxs_path, "r", encoding="utf-8") as f:
        wxs = f.read()

    injected = []
    for bmp, var_id in BITMAPS.items():
        if f'Id="{var_id}"' in wxs:
            continue  # already branded
        line = f'        <WixVariable Id="{var_id}" Value="{bmp}" />'
        if ANCHOR in wxs:
            wxs = wxs.replace(ANCHOR, ANCHOR + "\n" + line.strip(), 1)
        else:
            # Fallback: inject before the closing Package/Wix tag
            wxs = wxs.replace("</Package>", line + "\n    </Package>", 1)
        injected.append(var_id)

    with open(wxs_path, "w", encoding="utf-8") as f:
        f.write(wxs)

    print(f"Branded installer at {scaffold}: copied {', '.join(BITMAPS)}; "
          f"injected {', '.join(injected) if injected else '(already present)'}")


if __name__ == "__main__":
    main()
