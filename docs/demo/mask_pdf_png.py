"""Tapa en las imágenes de un PDF las palabras que coincidan con patrones sensibles (hostname, IP privadas…).

Uso: python3 mask_pdf_png.py reporte.pdf out/pdf <dpi> '<regex1>' ['<regex2>' ...]   (las PNG son out/pdf-1.png, out/pdf-2.png…)
"""
import re
import subprocess
import sys
from xml.etree import ElementTree as ET

from PIL import Image, ImageDraw

pdf, prefix, dpi, patterns = sys.argv[1], sys.argv[2], float(sys.argv[3]), [re.compile(p) for p in sys.argv[4:]]
xml = subprocess.run(["pdftotext", "-bbox", pdf, "-"], capture_output=True, text=True, check=True).stdout
root = ET.fromstring(re.sub(r"<!DOCTYPE[^>]*>", "", xml).replace('xmlns="http://www.w3.org/1999/xhtml"', ""))
scale = dpi / 72
for n, page in enumerate(root.iter("page"), 1):
    path = f"{prefix}-{n}.png"
    try:
        img = Image.open(path).convert("RGB")
    except FileNotFoundError:
        continue
    d = ImageDraw.Draw(img)
    for w in page.iter("word"):
        if any(p.search(w.text or "") for p in patterns):
            x0, y0, x1, y1 = (float(w.get(k)) * scale for k in ("xMin", "yMin", "xMax", "yMax"))
            d.rectangle([x0 - 2, y0 - 1, x1 + 2, y1 + 1], fill=(120, 130, 150))
    img.save(path)
