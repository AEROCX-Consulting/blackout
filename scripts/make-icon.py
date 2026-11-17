#!/usr/bin/env python3
"""Maakt packaging/icon.png (1024x1024), icon-256.png en icon.ico uit het AEROCX-symbool.

Het symbool is het eerste deel van assets/logo.svg (de gekantelde, verschoven cirkel).
Zwart vlak, wit symbool. Nodig: rsvg-convert (librsvg) en Pillow.

    python3 scripts/make-icon.py
"""
import os
import re
import subprocess
import sys
import tempfile

from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGO = os.path.join(ROOT, "assets", "logo.svg")
OUT = os.path.join(ROOT, "packaging")

SIZE = 1024
SYMBOL = 0.58  # deel van de breedte dat het symbool inneemt


def symbol_group(svg: str) -> str:
    """Haal de <g> met het symbool (clipPaths q1u/q1l) uit het logo."""
    start = svg.index('<g transform="translate(1.2000')
    depth, i = 0, start
    for m in re.finditer(r"<g\b|</g>", svg[start:]):
        depth += 1 if m.group(0).startswith("<g") else -1
        if depth == 0:
            i = start + m.end()
            break
    return svg[start:i]


def main() -> None:
    svg = open(LOGO, encoding="utf-8").read()
    group = symbol_group(svg)
    # Het symbool beslaat in zijn eigen coördinaten ongeveer x 1..97, y 1..98 (vak van 100).
    scale = SIZE * SYMBOL / 100.0
    offset = (SIZE - 100.0 * scale) / 2.0
    icon_svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{SIZE}" height="{SIZE}" '
        f'viewBox="0 0 {SIZE} {SIZE}" color="#FFFFFF">'
        f'<rect width="{SIZE}" height="{SIZE}" fill="#0B0B0C"/>'
        f'<g transform="translate({offset:.3f} {offset:.3f}) scale({scale:.5f})">{group}</g>'
        "</svg>"
    )
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "icon.svg")
        with open(src, "w", encoding="utf-8") as f:
            f.write(icon_svg)
        png = os.path.join(OUT, "icon.png")
        subprocess.run(["rsvg-convert", "-w", str(SIZE), "-h", str(SIZE), "-o", png, src], check=True)

    img = Image.open(png).convert("RGBA")
    img.resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, "icon-256.png"))
    img.save(
        os.path.join(OUT, "icon.ico"),
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print("klaar:", ", ".join(["icon.png", "icon-256.png", "icon.ico"]))


if __name__ == "__main__":
    sys.exit(main())
