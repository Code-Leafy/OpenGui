#!/usr/bin/env python3
# Generates a minimal valid 1x1 ICO file and a minimal 1x1 PNG file
import os
import struct

icon_dir = os.path.join(os.path.dirname(__file__), 'icons')

# ── ICO ───────────────────────────────────────────────────────────────────────
# ICO: 1x1 pixel, 32bpp BGRA
# Structure: ICONDIR (6) + ICONDIRENTRY (16) + BITMAPINFOHEADER (40) + pixel (4) + AND mask (4)
bmp_data = (
    struct.pack('<IIIHHIIIIII',
        40,   # biSize
        1,    # biWidth
        2,    # biHeight (doubled for ICO format)
        1,    # biPlanes
        32,   # biBitCount
        0,    # biCompression
        0,    # biSizeImage
        0, 0, # biX/YPelsPerMeter
        0, 0  # biClrUsed/Important
    ) +
    b'\x00\x00\xff\xff' +  # 1 pixel BGRA: red, fully opaque
    b'\x00\x00\x00\x00'    # AND mask
)

ico = (
    struct.pack('<HHH', 0, 1, 1) +   # ICONDIR: reserved, type=1 (ICO), count=1
    struct.pack('<BBBBHHII',
        1, 1, 0, 0,         # width, height, colorCount, reserved
        1, 32,              # planes, bitCount
        len(bmp_data),      # bytes in image
        6 + 16              # offset to image data
    ) +
    bmp_data
)

with open(os.path.join(icon_dir, 'icon.ico'), 'wb') as f:
    f.write(ico)
print(f"icon.ico: {len(ico)} bytes")

# ── PNG ───────────────────────────────────────────────────────────────────────
# Minimal valid 1x1 red PNG
import zlib

def png_chunk(chunk_type, data):
    c = chunk_type + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

png = (
    b'\x89PNG\r\n\x1a\n' +
    png_chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 6, 0, 0, 0)) +  # color type 6 = RGBA
    png_chunk(b'IDAT', zlib.compress(b'\x00\xff\x00\x00\xff')) +  # filter=0, R=255, G=0, B=0, A=255
    png_chunk(b'IEND', b'')
)

with open(os.path.join(icon_dir, 'icon.png'), 'wb') as f:
    f.write(png)
print(f"icon.png: {len(png)} bytes")
print("Done")
