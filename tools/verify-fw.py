#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2025 David Guillen Fandos <david@davidgf.net>
# Verifies a SuperFW firmware image (.fw / .gba) before it gets flashed into the
# cart.  This only re-does, on a PC, the checks the in-cart updater performs
# before it dares to erase anything: SUPERFW magic, hardware variant, advertised
# size, truncated SHA256 header checksum and the GBA cartridge complement.

import argparse
import glob
import hashlib
import os
import struct
import sys

# See t_superfw_header in src/flash.c; the header lives at 0xC0 of the image.
HDR_OFF = 0xC0
OFF_BRANCH = HDR_OFF + 0x00
OFF_VERSION = HDR_OFF + 0x04
OFF_GIT = HDR_OFF + 0x08
OFF_SIZE = HDR_OFF + 0x0C
OFF_HW = HDR_OFF + 0x10
OFF_FWVARIANT = HDR_OFF + 0x14
OFF_CHECKSUM = HDR_OFF + 0x20
OFF_MAGIC = HDR_OFF + 0x30
MAGIC = b"SUPERFW~DAVIDGF\x00"

# Flash budget per hardware variant, see MAXFSIZE in the Makefile.  Writing an
# image bigger than the firmware partition is what actually bricks a cart.
MAX_KIB = {"SD": 512, "Lite": 496, "Chis": 2048}


def verify(path):
    with open(path, "rb") as f:
        img = f.read()

    problems = []
    if len(img) < OFF_MAGIC + len(MAGIC):
        print("%s: TOO SMALL (%d bytes) -- not a firmware image" % (path, len(img)))
        return False

    branch = struct.unpack_from("<I", img, OFF_BRANCH)[0]
    version, gitver, fwsize = struct.unpack_from("<III", img, OFF_VERSION)
    hw = img[OFF_HW:OFF_HW + 4].rstrip(b"\x00").decode("ascii", "replace")
    fwvariant = img[OFF_FWVARIANT:OFF_FWVARIANT + 4].decode("ascii", "replace")
    magic = img[OFF_MAGIC:OFF_MAGIC + 16]
    stored = img[OFF_CHECKSUM:OFF_CHECKSUM + 16]

    if magic != MAGIC:
        problems.append("bad magic %r" % (magic,))
    # (branch) + version + git slug + size + variants + pad + zeroed checksum
    # + everything from the magic on, matching validate_superfw_checksum().
    blanked = (img[:OFF_CHECKSUM] + b"\x00" * 16 + img[OFF_CHECKSUM + 16:])
    if hashlib.sha256(blanked).digest()[:16] != stored:
        problems.append("SHA256 header checksum mismatch (tampered/truncated?)")
    if fwsize != len(img):
        problems.append("header size %d != file size %d" % (fwsize, len(img)))
    if len(img) % 512:
        problems.append("size not a multiple of 512")
    if (sum(img[0xA0:0xBD]) + img[0xBD] + 0x19) & 0xFF:
        problems.append("GBA cartridge header checksum is wrong")
    if (branch >> 28) != 0xE:
        problems.append("no ARM branch at 0x%03X (bad loader stub)" % OFF_BRANCH)
    if fwvariant != "WRLD":
        problems.append("unexpected firmware variant %r" % (fwvariant,))

    limit = MAX_KIB.get(hw)
    if limit is None:
        problems.append("unknown hardware variant %r" % (hw,))
    elif len(img) > limit * 1024:
        problems.append("image is %d bytes, over the %d KiB %s partition" %
                        (len(img), limit, hw))

    print("%s" % os.path.basename(path))
    print("   size %8d bytes   version %d (0.%d)   git 0x%08x" %
          (len(img), version, version, gitver))
    print("   hardware %-5s   firmware %s" % (hw, fwvariant))
    if problems:
        for p in problems:
            print("   FAIL: %s" % p)
        return False
    print("   OK: safe to flash on a %s cart" % hw)
    return True


def main():
    ap = argparse.ArgumentParser(description="check a SuperFW .fw image")
    ap.add_argument("files", nargs="*", default=["superfw.gba"])
    args = ap.parse_args()

    paths = []
    for pattern in args.files:
        paths += sorted(glob.glob(pattern)) or [pattern]

    ok = [verify(p) for p in paths]
    print("%d/%d images verified" % (sum(ok), len(ok)))
    return 0 if all(ok) else 1


if __name__ == "__main__":
    sys.exit(main())
