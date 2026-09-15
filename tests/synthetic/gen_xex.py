#!/usr/bin/env python3
"""
Synthetic XEX2 generator for XenonRecomp testing.

Generates a minimal, uncompressed, unencrypted Xbox 360 executable that
contains:
  - an entry point function
  - regular functions (calls, loops, conditional branches)
  - the CRT register save/restore helper sequences (__restgprlr_14, ...)
  - an absolute jump table (detectable by XenonAnalyse)
  - a .pdata section with runtime function entries

Corruption switches reproduce crash/hang scenarios seen in the wild
(e.g. hedge-dev/XenonRecomp#150 "terminate called after throwing an
instance of 'std::bad_alloc'"):

  --no-pdata          omit the .pdata section entirely
  --zero-fnlen        add a .pdata entry with FunctionLength == 0
  --huge-imagesize    set security->imageSize to a garbage huge value
  --truncated         set header->headerSize larger than the file
  --encrypted         claim XEX_ENCRYPTION_NORMAL encryption
  --delta             claim XEX_COMPRESSION_DELTA compression
  --basic             use BASIC compression (data + zero runs)

Usage: gen_xex.py <output.xex> [options] [--symbols out.txt]
"""

import argparse
import struct
import sys

IMAGE_BASE = 0x82000000
TEXT_VA = 0x1000
DATA_VA = 0x10000
PDATA_VA = 0x10800

SEC_INFO_SIZE = 0x184

# ---------------------------------------------------------------------------
# Tiny PPC assembler (big-endian encodings)
# ---------------------------------------------------------------------------

def u32(v):
    return struct.pack('>I', v & 0xFFFFFFFF)

def nop():            return 0x60000000
def blr():            return 0x4E800020
def bctr():           return 0x4E800420
def mflr(rd):         return 0x7C0802A6 | (rd << 21)
def mtlr(rs):         return 0x7C0803A6 | (rs << 21)
def mtctr(rs):        return 0x7C0903A6 | (rs << 21)
def li(rd, simm):     return 0x38000000 | (rd << 21) | (simm & 0xFFFF)
def lis(rd, imm):     return 0x3C000000 | (rd << 21) | (imm & 0xFFFF)
def addi(rd, ra, simm): return 0x38000000 | (rd << 21) | (ra << 16) | (simm & 0xFFFF)
def rlwinm(ra, rs, sh, mb, me): return 0x54000000 | (rs << 21) | (ra << 16) | (sh << 11) | (mb << 6) | (me << 1)
def ld(rd, d, ra):    return 0xE8000000 | (rd << 21) | (ra << 16) | (d & 0xFFFC)
def std(rs, d, ra):   return 0xF8000000 | (rs << 21) | (ra << 16) | (d & 0xFFFC)
def lwz(rd, d, ra):   return 0x80000000 | (rd << 21) | (ra << 16) | (d & 0xFFFF)
def stw(rs, d, ra):   return 0x90000000 | (rs << 21) | (ra << 16) | (d & 0xFFFF)
def lfd(fd, d, ra):   return 0xC8000000 | (fd << 21) | (ra << 16) | (d & 0xFFFF)
def stfd(fs, d, ra):  return 0xD8000000 | (fs << 21) | (ra << 16) | (d & 0xFFFF)
def lvx(vd, ra, rb):  return 0x7C000000 | (vd << 21) | (ra << 16) | (rb << 11) | (103 << 1)
def stvx(vs, ra, rb): return 0x7C000000 | (vs << 21) | (ra << 16) | (rb << 11) | (231 << 1)
def lwzx(rd, ra, rb): return 0x7C00002E | (rd << 21) | (ra << 16) | (rb << 11)
def cmplwi(cr, ra, uimm): return 0x28000000 | ((cr & 7) << 23) | (ra << 16) | (uimm & 0xFFFF)
def mr(ra, rs):       return 0x7C000378 | (rs << 21) | (ra << 16) | (rs << 11)

def _vds128(vd):
    return ((vd & 0x60) >> 3) | ((vd & 0x1F) << 21)

def lvx128(vd, ra, rb):  return 0x100000C3 | _vds128(vd) | (ra << 16) | (rb << 11)
def stvx128(vs, ra, rb): return 0x100001C3 | _vds128(vs) | (ra << 16) | (rb << 11)

def b(from_addr, to_addr, link=False):
    d = to_addr - from_addr
    return 0x48000000 | (d & 0x03FFFFFC) | (1 if link else 0)

def bgt(from_addr, to_addr, cr=0, link=False):
    # bc 12, 4*cr+1 (GT bit), disp
    d = to_addr - from_addr
    return 0x40000000 | (12 << 21) | ((4 * cr + 1) << 16) | (d & 0xFFFC) | (1 if link else 0)

# ---------------------------------------------------------------------------
# Text section layout
# ---------------------------------------------------------------------------

class TextBuilder:
    def __init__(self):
        self.words = []
        self.symbols = {}

    def here(self):
        return IMAGE_BASE + TEXT_VA + len(self.words) * 4

    def emit(self, *words):
        for w in words:
            self.words.append(w & 0xFFFFFFFF)

    def mark(self, name):
        self.symbols[name] = self.here()

    def data(self):
        out = bytearray()
        for w in self.words:
            out += u32(w)
        return bytes(out)


def build_text():
    t = TextBuilder()

    # --- entry point ---------------------------------------------------------
    t.mark('_start')
    t.emit(li(3, 0))
    bl_main = t.here(); t.emit(0)            # placeholder: bl func_main
    t.emit(blr())

    # --- func_main: call, loop, conditional branch ---------------------------
    t.mark('func_main')
    func_main = t.here()
    t.emit(mflr(0))
    t.emit(std(0, 0x10, 1))
    t.emit(std(31, -8, 1))
    t.emit(li(31, 0))
    loop_top = t.here()
    t.emit(li(3, 7))
    bl_helper = t.here(); t.emit(0)          # placeholder: bl func_helper
    t.emit(addi(31, 31, 1))
    t.emit(cmplwi(6, 31, 10))
    bgt_back = t.here(); t.emit(0)           # placeholder: bgt loop_top
    t.emit(li(3, 0))
    t.emit(ld(0, 0x10, 1))
    t.emit(mtlr(0))
    t.emit(ld(31, -8, 1))
    t.emit(blr())

    # --- func_helper ---------------------------------------------------------
    t.mark('func_helper')
    func_helper = t.here()
    t.emit(li(4, 0x2A))
    t.emit(addi(5, 4, 1))
    t.emit(blr())

    # --- jump table switch function ------------------------------------------
    # pattern: cmplwi cr6, r3, 3 ; bgt cr6, default
    #          lis r11, HI ; addi r11, r11, LO ; rlwinm r0, r3, 2, 0, 29
    #          lwzx r0, r11, r0 ; mtctr r0 ; bctr
    t.mark('func_switch')
    func_switch = t.here()
    t.emit(cmplwi(6, 3, 3))
    bgt_default = t.here(); t.emit(0)        # placeholder: bgt default_case
    lis_table = t.here(); t.emit(0)          # placeholder: lis r11, HI(table)
    addi_table = t.here(); t.emit(0)         # placeholder: addi r11, r11, LO(table)
    t.emit(rlwinm(0, 3, 2, 0, 25))           # not slwi-aliasable, matches the XenonAnalyse pattern
    t.emit(lwzx(0, 11, 0))
    t.emit(mtctr(0))
    t.emit(bctr())

    # case bodies (must live inside func_switch for the recompiler's switch)
    for i in range(4):
        t.mark('case_%d' % i)
        t.emit(li(3, 0x100 + i))
        t.emit(blr())

    t.mark('default_case')
    default_case = t.here()
    t.emit(li(3, 0x1FF))
    t.emit(blr())
    t.mark('func_switch_end')

    # --- CRT helpers (packed back-to-back so entry sizes line up) -------------
    # __restgprlr_14: ld r14..r31 (stride 8, from -0x98), ld r0, mtlr, blr -> 84 bytes
    t.mark('__restgprlr_14')
    for i in range(14, 32):
        t.emit(ld(i, -0x98 + (i - 14) * 8, 1))
    t.emit(ld(0, 0x10, 1))
    t.emit(mtlr(0))
    t.emit(blr())

    # __savegprlr_14: std r14..r31 (stride 8, from -0xA8), mflr r0, blr -> 80 bytes
    t.mark('__savegprlr_14')
    for i in range(14, 32):
        t.emit(std(i, -0xA8 + (i - 14) * 8, 1))
    t.emit(mflr(0))
    t.emit(blr())

    # __restfpr_14: lfd f14..f31 (stride 8, from -0x90, base r12), blr -> 76 bytes
    t.mark('__restfpr_14')
    for i in range(14, 32):
        t.emit(lfd(i, -0x90 + (i - 14) * 8, 12))
    t.emit(blr())

    # __savefpr_14: stfd f14..f31 (stride 8, from -0x90, base r12), blr -> 76 bytes
    t.mark('__savefpr_14')
    for i in range(14, 32):
        t.emit(stfd(i, -0x90 + (i - 14) * 8, 12))
    t.emit(blr())

    # __restvmx_14: (li r11, D ; lvx vS, r11, r12) x18, blr -> 148 bytes
    t.mark('__restvmx_14')
    for i in range(14, 32):
        t.emit(li(11, -0x120 + (i - 14) * 0x10))
        t.emit(lvx(i, 11, 12))
    t.emit(blr())

    # __savevmx_14 -> 148 bytes
    t.mark('__savevmx_14')
    for i in range(14, 32):
        t.emit(li(11, -0x120 + (i - 14) * 0x10))
        t.emit(stvx(i, 11, 12))
    t.emit(blr())

    # __restvmx_64: (li r11, D ; lvx128 vS, r11, r12) x64, blr -> 516 bytes
    t.mark('__restvmx_64')
    for i in range(64, 128):
        t.emit(li(11, -0x400 + (i - 64) * 0x10))
        t.emit(lvx128(i, 11, 12))
    t.emit(blr())

    # __savevmx_64 -> 516 bytes
    t.mark('__savevmx_64')
    for i in range(64, 128):
        t.emit(li(11, -0x400 + (i - 64) * 0x10))
        t.emit(stvx128(i, 11, 12))
    t.emit(blr())

    # A function only reachable through the jump table (no direct bl).
    t.mark('func_orphan')
    t.emit(li(3, 0x300))
    t.emit(blr())

    # A function that is only described through .pdata (no bl references it).
    t.mark('func_pdata_only')
    func_pdata_only = t.here()
    t.emit(li(5, 0x55))
    t.emit(blr())

    # --- resolve placeholders -------------------------------------------------
    words = t.words

    def index_of(addr):
        return (addr - IMAGE_BASE - TEXT_VA) // 4

    words[index_of(bl_main)] = b(bl_main, func_main, link=True)
    words[index_of(bl_helper)] = b(bl_helper, func_helper, link=True)
    words[index_of(bgt_back)] = bgt(bgt_back, loop_top, cr=6)
    words[index_of(bgt_default)] = bgt(bgt_default, default_case, cr=6)

    table_va = IMAGE_BASE + DATA_VA
    words[index_of(lis_table)] = lis(11, (table_va >> 16) & 0xFFFF)
    words[index_of(addi_table)] = addi(11, 11, table_va & 0xFFFF)

    return t


def pe_headers(sections):
    """sections: list of (name, va, size, characteristics)"""
    e_lfanew = 0x80
    dos = bytearray(0x80)
    dos[0:2] = b'MZ'
    dos[0x3C:0x40] = struct.pack('<I', e_lfanew)

    nt = bytearray()
    nt += b'PE\0\0'
    nt += struct.pack('<HHIIIHH',
                      0x01F2,            # Machine (Xbox 360 / PPC)
                      len(sections),     # NumberOfSections
                      0, 0, 0,
                      0xE0,              # SizeOfOptionalHeader = 224
                      0)
    opt = bytearray(224)
    opt[0:2] = struct.pack('<H', 0x10B)  # Magic PE32
    nt += opt

    sec_hdrs = bytearray()
    for name, va, size, chars in sections:
        nm = name.encode()[:8].ljust(8, b'\0')
        sec_hdrs += nm
        sec_hdrs += struct.pack('<IIIIIIHHI',
                                size, va, size, va,
                                0, 0, 0, 0,
                                chars)

    return bytes(bytearray(dos) + nt + sec_hdrs)


def build_image(t, args):
    text = t.data()

    # .data: jump table (4 entries) then padding
    jump_table = b''
    for i in range(4):
        jump_table += u32(t.symbols['case_%d' % i])
    data = jump_table + b'\0' * (0x800 - len(jump_table))

    # .pdata entries (BE): (BeginAddress, PrologLength | FunctionLength<<8)
    def pdata_entry(addr, instr_count, prolog=0):
        return u32(addr) + struct.pack('>I', (prolog & 0xFF) | ((instr_count & 0x3FFFFF) << 8))

    pdata = b''
    pdata += pdata_entry(t.symbols['_start'], 3, 0)
    pdata += pdata_entry(t.symbols['func_main'], (t.symbols['func_helper'] - t.symbols['func_main']) // 4, 8)
    pdata += pdata_entry(t.symbols['func_helper'], 3, 0)
    pdata += pdata_entry(t.symbols['func_switch'], (t.symbols['func_switch_end'] - t.symbols['func_switch']) // 4, 4)
    if args.zero_fnlen:
        # FunctionLength == 0 must not wedge the analyser in an infinite loop.
        pdata += pdata_entry(t.symbols['func_pdata_only'], 0, 0)
    else:
        pdata += pdata_entry(t.symbols['func_pdata_only'], 2, 0)
    pdata += b'\0' * (0x200 - len(pdata))

    image_size = PDATA_VA + len(pdata)
    sections = [
        ('.text',  TEXT_VA,  len(text),  0x20000020),  # CODE | EXECUTE
        ('.data',  DATA_VA,  len(data),  0x40000040),  # INITIALIZED_DATA | READ
    ]
    if not args.no_pdata:
        sections.append(('.pdata', PDATA_VA, len(pdata), 0x40000040))

    # Replicate two PE section table quirks seen in real console XEX2 images:
    #   * a stripped .reloc section: its data is consumed by the system
    #     loader, leaving VirtualSize = 0 and an out-of-range stale address;
    #   * page rounding that makes the last section stick out slightly past
    #     the end of the image, which loaders must clamp, not reject.
    sections.append(('.reloc', 0xFFFF0000, 0, 0x42000042))
    sections.append(('.pad', image_size - 4, 0x40, 0x40000040))

    image = bytearray(image_size)
    headers = pe_headers(sections)
    image[0:len(headers)] = headers
    image[TEXT_VA:TEXT_VA + len(text)] = text
    image[DATA_VA:DATA_VA + len(data)] = data
    if not args.no_pdata:
        image[PDATA_VA:PDATA_VA + len(pdata)] = pdata

    return bytes(image), image_size


def build_xex(image, image_size, entry_point, args):
    opt_count = 3
    sec_off = 24 + 8 * opt_count
    fmt_off = sec_off + SEC_INFO_SIZE

    encryption = 1 if args.encrypted else 0
    compression = 3 if args.delta else (1 if args.basic else 0)

    fmt_info = struct.pack('>IHH', 8, encryption, compression)
    if args.basic:
        # BASIC blocks cover the WHOLE image in 64KB chunks, so every section
        # (including .pdata) survives the round trip, exactly like the real
        # console format does.
        blocks = []
        off = 0
        while off < image_size:
            n = min(0x10000, image_size - off)
            blocks.append((n, 0))
            off += n
        fmt_info = struct.pack('>IHH', 8 + 8 * len(blocks), encryption, 1)
        for data_bytes, zero_bytes in blocks:
            fmt_info += struct.pack('>II', data_bytes, zero_bytes)

    sec_info = bytearray()
    sec_info += struct.pack('>I', SEC_INFO_SIZE)
    sec_info += struct.pack('>I', 0xFFFFFFFF if args.huge_imagesize else image_size)
    sec_info += b'\0' * 0x100                            # rsaSignature
    sec_info += struct.pack('>I', 0)                     # unknown
    sec_info += struct.pack('>I', 0)                     # imageFlags
    sec_info += struct.pack('>I', IMAGE_BASE)            # loadAddress
    sec_info += b'\0' * 0x14                             # sectionDigest
    sec_info += struct.pack('>I', 0)                     # importTableCount
    sec_info += b'\0' * 0x14                             # importTableDigest
    sec_info += b'\0' * 0x10                             # xgd2MediaId
    sec_info += b'\0' * 0x10                             # aesKey
    sec_info += struct.pack('>I', 0)                     # exportTable
    sec_info += b'\0' * 0x14                             # headerDigest
    sec_info += struct.pack('>I', 0xFFFF)                # region
    sec_info += struct.pack('>I', 0)                     # allowedMediaTypes
    sec_info += struct.pack('>I', 0)                     # pageDescriptorCount
    assert len(sec_info) == SEC_INFO_SIZE, len(sec_info)

    header = bytearray()
    header += b'XEX2'
    header += struct.pack('>I', 0)                       # moduleFlags
    header_size = fmt_off + len(fmt_info)
    header_size = (header_size + 0xFF) & ~0xFF
    header += struct.pack('>I', 0x7FFFFFFF if args.truncated else header_size)
    header += struct.pack('>I', 0)                       # reserved
    header += struct.pack('>I', sec_off)                 # securityOffset
    header += struct.pack('>I', opt_count)               # headerCount
    header += struct.pack('>II', 0x000003FF, fmt_off)    # FILE_FORMAT_INFO
    header += struct.pack('>II', 0x00010100, entry_point)# ENTRY_POINT
    header += struct.pack('>II', 0x00010201, IMAGE_BASE) # IMAGE_BASE_ADDRESS
    header += b'\0' * (sec_off - len(header))
    header += sec_info
    header += b'\0' * (fmt_off - len(header))
    header += fmt_info
    header += b'\0' * (header_size - len(header))

    payload = image

    return bytes(header) + payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('output')
    ap.add_argument('--no-pdata', action='store_true')
    ap.add_argument('--zero-fnlen', action='store_true')
    ap.add_argument('--huge-imagesize', action='store_true')
    ap.add_argument('--truncated', action='store_true')
    ap.add_argument('--encrypted', action='store_true')
    ap.add_argument('--delta', action='store_true')
    ap.add_argument('--basic', action='store_true')
    ap.add_argument('--symbols', help='optional path to write symbol name=addr lines')
    args = ap.parse_args()

    t = build_text()
    image, image_size = build_image(t, args)
    xex = build_xex(image, image_size, t.symbols['_start'], args)

    with open(args.output, 'wb') as f:
        f.write(xex)

    if args.symbols:
        with open(args.symbols, 'w') as f:
            for k, v in sorted(t.symbols.items(), key=lambda kv: kv[1]):
                f.write('%s=0x%X\n' % (k, v))
            f.write('IMAGE_BASE=0x%X\n' % IMAGE_BASE)
            f.write('IMAGE_SIZE=0x%X\n' % image_size)

    print('wrote %s (%d bytes)' % (args.output, len(xex)), file=sys.stderr)


if __name__ == '__main__':
    main()
