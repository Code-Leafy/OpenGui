# ICONDIR (6 bytes): reserved=0, type=1 (icon), count=1
# ICONDIRENTRY (16 bytes): w=16, h=16, clrcount=0, reserved=0, planes=1, bitcount=24, bytesInRes=840, offset=22
# Image data = BITMAPINFOHEADER (40 bytes) + XOR mask 16x16x24bpp (768 bytes) + AND mask 16 rows x 4 bytes (32 bytes) = 840 bytes

$header = [byte[]] @(
    0x00, 0x00,        # reserved
    0x01, 0x00,        # type: icon
    0x01, 0x00         # count: 1
)

$entry = [byte[]] @(
    0x10,              # width: 16
    0x10,              # height: 16
    0x00,              # color count (0 = no palette)
    0x00,              # reserved
    0x01, 0x00,        # planes
    0x18, 0x00,        # bit count: 24
    0x48, 0x03, 0x00, 0x00,  # bytes in res: 840
    0x16, 0x00, 0x00, 0x00   # image offset: 22 (= 6 + 16)
)

$bih = [byte[]] @(
    0x28, 0x00, 0x00, 0x00,  # biSize: 40
    0x10, 0x00, 0x00, 0x00,  # biWidth: 16
    0x20, 0x00, 0x00, 0x00,  # biHeight: 32 (16*2 for ICO)
    0x01, 0x00,              # biPlanes: 1
    0x18, 0x00,              # biBitCount: 24
    0x00, 0x00, 0x00, 0x00,  # biCompression: BI_RGB
    0x00, 0x00, 0x00, 0x00,  # biSizeImage: 0
    0x00, 0x00, 0x00, 0x00,  # biXPelsPerMeter: 0
    0x00, 0x00, 0x00, 0x00,  # biYPelsPerMeter: 0
    0x00, 0x00, 0x00, 0x00,  # biClrUsed: 0
    0x00, 0x00, 0x00, 0x00   # biClrImportant: 0
)

# XOR mask: 16x16 pixels, 24bpp BGR, all set to (0x20, 0x40, 0x80) = dark teal
$xor = New-Object byte[] 768
for ($i = 0; $i -lt 768; $i += 3) {
    $xor[$i]     = 0x80  # B
    $xor[$i + 1] = 0x40  # G
    $xor[$i + 2] = 0x20  # R
}

# AND mask: 16 rows, each row padded to 4 bytes = 16*4 = 64 bytes; all 0 = fully opaque
$and = New-Object byte[] 64

$allData = $header + $entry + $bih + $xor + $and
[System.IO.File]::WriteAllBytes("C:\Users\artin\OneDrive\Documents\Projects\OpenConnect\src-tauri\icons\icon.ico", $allData)
Write-Host "Done. Total bytes: $($allData.Length)"
