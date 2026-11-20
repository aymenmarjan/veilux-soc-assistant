"""Builds the VEILUX application icons from the mascot artwork.

    python packaging/make_icons.py

Reads packaging/icons/veilux-mascot.png (the owl, transparent background)
and writes, next to it:
  veilux.ico         Windows: 16, 24, 32, 48, 64, 128 and 256 pixels
  veilux.icns        macOS: 16 to 1024 pixels, including Retina sizes
  linux/<n>x<n>.png  Linux (freedesktop hicolor theme): 16 to 512 pixels

Each icon is the mascot as a portrait on a white rounded tile, as in the
extension's popup logo. Small sizes use a closer crop of the head (hat, glasses and beak), so the
owl stays recognizable at 16 to 32 pixels; nothing else is redrawn. The
output is committed, so building the packages needs no image library.
Needs Pillow.
"""
import io
import struct
import sys
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw

HERE = Path(__file__).resolve().parent / "icons"
SOURCE = HERE / "veilux-mascot.png"
WHITE = (255, 255, 255, 255)
BORDER = (203, 213, 225, 255)   # a light slate edge, so the tile shows on white backgrounds
SUPERSAMPLE = 4

# Crops of the 1312 x 1199 artwork, as (left, top, right, bottom) fractions:
# the full portrait for large icons, the head and collar for medium ones and
# the hat, glasses and beak for the smallest.
CROPS = {
    "portrait": (0.0, 0.0, 1.0, 1.0),
    "bust": (0.13, 0.0, 0.89, 0.83),
    "head": (0.19, 0.0, 0.85, 0.66),
}


def crop_for(size):
    return "head" if size <= 32 else "bust" if size <= 64 else "portrait"


def rounded_mask(size, radius):
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    return mask


def tile(size, crop, inset=0.0):
    """The mascot on a white rounded tile. `inset` leaves a transparent margin
    around the tile (macOS draws its icons on a smaller grid)."""
    big = size * SUPERSAMPLE
    art = Image.open(SOURCE).convert("RGBA")
    w, h = art.size
    l, t, r, b = CROPS[crop]
    art = art.crop((round(l * w), round(t * h), round(r * w), round(b * h)))
    side = round(big * (1 - 2 * inset))
    radius = round(side * 0.2)
    canvas = Image.new("RGBA", (side, side), WHITE)
    # Fit the width with a small margin, keep the top of the hat inside the
    # tile and let the bust run off the bottom edge, as in a portrait.
    margin = 0.05 if crop == "portrait" else 0.03
    scale = side * (1 - 2 * margin) / art.width
    art = art.resize((round(art.width * scale), round(art.height * scale)), Image.LANCZOS)
    top = max(round(side * margin), side - art.height)
    canvas.alpha_composite(art, (round((side - art.width) / 2), top))
    mask = rounded_mask(side, radius)
    shaped = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    shaped.paste(canvas, (0, 0), mask)
    edge = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    ImageDraw.Draw(edge).rounded_rectangle((0, 0, side - 1, side - 1), radius=radius, outline=BORDER,
                                           width=max(SUPERSAMPLE, round(side / 256)))
    shaped.alpha_composite(edge)
    out = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    out.alpha_composite(shaped, ((big - side) // 2, (big - side) // 2))
    return out.resize((size, size), Image.LANCZOS)


def png_bytes(image):
    buffer = io.BytesIO()
    image.save(buffer, "PNG", optimize=True)
    return buffer.getvalue()


def write_ico(path, sizes):
    """ICO with one PNG-compressed image per size (Windows Vista and later)."""
    images = [png_bytes(tile(s, crop_for(s))) for s in sizes]
    header = struct.pack("<HHH", 0, 1, len(sizes))
    offset = len(header) + 16 * len(sizes)
    entries, data = b"", b""
    for size, blob in zip(sizes, images):
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset + len(data))
        data += blob
    path.write_bytes(header + entries + data)


def write_icns(path):
    """ICNS with PNG entries; macOS icons use an inset tile (Apple's icon grid)."""
    types = [("icp4", 16), ("icp5", 32), ("icp6", 64), ("ic07", 128), ("ic08", 256), ("ic09", 512),
             ("ic10", 1024), ("ic11", 32), ("ic12", 64), ("ic13", 256), ("ic14", 512)]
    body = b""
    for kind, size in types:
        blob = png_bytes(tile(size, crop_for(size), inset=0.0 if size <= 32 else 0.1))
        body += kind.encode() + struct.pack(">I", len(blob) + 8) + blob
    path.write_bytes(b"icns" + struct.pack(">I", len(body) + 8) + body)


def main():
    if not SOURCE.exists():
        sys.exit(f"Missing {SOURCE}")
    write_ico(HERE / "veilux.ico", [16, 24, 32, 48, 64, 128, 256])
    write_icns(HERE / "veilux.icns")
    linux = HERE / "linux"
    linux.mkdir(exist_ok=True)
    for size in (16, 24, 32, 48, 64, 128, 256, 512):
        tile(size, crop_for(size)).save(linux / f"{size}x{size}.png", optimize=True)
    print("Icons written to", HERE)


if __name__ == "__main__":
    main()
