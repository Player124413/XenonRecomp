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

# --- update-form / indexed-update memory ops --------------------------------

def _dform(op, rd, d, ra):
    return (op << 26) | (rd << 21) | (ra << 16) | (d & 0xFFFF)

def lhzu(rd, d, ra):   return _dform(41, rd, d, ra)
def lhau(rd, d, ra):   return _dform(43, rd, d, ra)
def sthu(rs, d, ra):   return _dform(45, rs, d, ra)
def lfsu(fr, d, ra):   return _dform(49, fr, d, ra)
def lfdu(fr, d, ra):   return _dform(51, fr, d, ra)
def stfsu(fr, d, ra):  return _dform(53, fr, d, ra)
def stfdu(fr, d, ra):  return _dform(55, fr, d, ra)

def _xform(xo, a, b, c, rc=0):
    return 0x7C000000 | (a << 21) | (b << 16) | (c << 11) | (xo << 1) | rc

def ldux(rt, ra, rb):   return _xform(53, rt, ra, rb)
def lwzux(rt, ra, rb):  return _xform(55, rt, ra, rb)
def lbzux(rt, ra, rb):  return _xform(119, rt, ra, rb)
def stdux(rs, ra, rb):  return _xform(181, rs, ra, rb)
def stbux(rs, ra, rb):  return _xform(247, rs, ra, rb)
def lhzux(rt, ra, rb):  return _xform(311, rt, ra, rb)
def lhaux(rt, ra, rb):  return _xform(375, rt, ra, rb)
def sthux(rs, ra, rb):  return _xform(439, rs, ra, rb)
def lfsux(fr, ra, rb):  return _xform(567, fr, ra, rb)
def lfdux(fr, ra, rb):  return _xform(631, fr, ra, rb)
def stfsux(fr, ra, rb): return _xform(695, fr, ra, rb)
def stfdux(fr, ra, rb): return _xform(759, fr, ra, rb)
def lvehx(vd, ra, rb):  return _xform(39, vd, ra, rb)

def addc(rt, ra, rb, rc=0):   return _xform(10, rt, ra, rb, rc)
def subfze(rt, ra, rc=0):     return 0x7C000000 | (rt << 21) | (ra << 16) | (200 << 1) | rc
def addme(rt, ra, rc=0):      return 0x7C000000 | (rt << 21) | (ra << 16) | (234 << 1) | rc
def eqv(ra, rs, rb, rc=0):    return _xform(284, ra, rs, rb, rc)
def rldicl(ra, rs, sh, mb, rc=0):
    return 0x78000000 | (rs << 21) | (ra << 16) | ((sh & 0x1F) << 11) | (((sh >> 5) & 1) << 1) | ((mb & 0x1F) << 6) | (((mb >> 5) & 1) << 5) | rc

# --- CTR-decrement conditional branches -------------------------------------

def bc_ctr(bo, bi, from_addr, to_addr):
    d = to_addr - from_addr
    return 0x40000000 | (bo << 21) | (bi << 16) | (d & 0xFFFC)

# BO values for the ctr-decrement conditionals (hint bit masked off)
BO_BDNZF = 0x0
BO_BDZF  = 0x2
BO_BDNZT = 0x8
BO_BDZT  = 0xA

# --- VMX / VMX128 -------------------------------------------------------------

def _vx(vd, va, vb, xo):
    return 0x10000000 | (vd << 21) | (va << 16) | (vb << 11) | xo

def vnor(vd, va, vb):     return _vx(vd, va, vb, 1284)
def vslh(vd, va, vb):     return _vx(vd, va, vb, 324)
def vsrh(vd, va, vb):     return _vx(vd, va, vb, 580)
def vspltish(vd, simm):   return _vx(vd, simm & 0x1F, 0, 844)
def vpkuwum(vd, va, vb):  return _vx(vd, va, vb, 78)
def vadduhs(vd, va, vb):  return _vx(vd, va, vb, 576)
def vsubuws(vd, va, vb):  return _vx(vd, va, vb, 1664)
def vctuxs(vd, vb, uimm): return _vx(vd, uimm & 0x1F, vb, 906)

# 128-register fields are split across the word; mirror the disassembler's
# extract_va128/extract_vb128/extract_vds128 bit layouts.
def _vd128(v): return ((v & 0x1F) << 21) | (((v >> 5) & 1) << 2) | (((v >> 6) & 1) << 3)
def _va128(v): return ((v & 0x1F) << 16) | (((v >> 5) & 1) << 5) | (((v >> 6) & 1) << 10)
def _vb128(v): return ((v & 0x1F) << 11) | ((v >> 5) & 1) | (((v >> 6) & 1) << 1)

def _vx128(xop, vd, va, vb):
    return 0x14000000 | (xop & 0x3D0) | _vd128(vd) | _va128(va) | _vb128(vb)

def vpkswss128(vd, va, vb): return _vx128(640, vd, va, vb)
def vnor128(vd, va, vb):    return _vx128(656, vd, va, vb)
def vsel128(vd, va, vb):    return _vx128(848, vd, va, vb)   # vC is the vD field
def vpkuwum128(vd, va, vb): return _vx128(896, vd, va, vb)

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

    # --- func_newinstrs: exercises every instruction family that Sonic
    # Generations needs and that used to hit "Unrecognized instruction" ------
    t.mark('func_newinstrs')
    func_newinstrs = t.here()

    # D-form update loads/stores (base r21, data r20/f20)
    t.emit(lhzu(20, 8, 21))
    t.emit(lhau(20, 8, 21))
    t.emit(sthu(20, 8, 21))
    t.emit(lfsu(20, 8, 21))
    t.emit(lfdu(20, 8, 21))
    t.emit(stfsu(20, 8, 21))
    t.emit(stfdu(20, 8, 21))

    # X-form indexed update loads/stores (base r21, index r22)
    t.emit(lhzux(20, 21, 22))
    t.emit(lhaux(20, 21, 22))
    t.emit(lbzux(20, 21, 22))
    t.emit(lwzux(20, 21, 22))
    t.emit(ldux(20, 21, 22))
    t.emit(sthux(20, 21, 22))
    t.emit(stbux(20, 21, 22))
    t.emit(stdux(20, 21, 22))
    t.emit(lfsux(20, 21, 22))
    t.emit(lfdux(20, 21, 22))
    t.emit(stfsux(20, 21, 22))
    t.emit(stfdux(20, 21, 22))
    t.emit(lvehx(20, 21, 22))

    # Carry arithmetic (plain + Rc forms)
    t.emit(addc(20, 21, 22))
    t.emit(addc(20, 21, 22, rc=1))
    t.emit(subfze(20, 21))
    t.emit(subfze(20, 21, rc=1))
    t.emit(addme(20, 21))
    t.emit(addme(20, 21, rc=1))
    t.emit(eqv(20, 21, 22))
    t.emit(eqv(20, 21, 22, rc=1))
    t.emit(rldicl(20, 21, 0, 32, rc=1))   # rldicl. (MB != 0 keeps it off the rotldi alias)
    t.emit(rldicl(20, 21, 5, 0, rc=1))    # rotldi. alias with RC

    # CTR-decrement conditional branches, each CR bit flavour, all jumping
    # forward to the final blr (targets patched below).
    bdzf_at = t.here();  t.emit(0)   # bdzf  cr0.eq, end
    bdzt_at = t.here();  t.emit(0)   # bdzt  cr0.gt, end
    bdnzt_at = t.here(); t.emit(0)   # bdnzt cr0.lt, end
    bdnzf_at = t.here(); t.emit(0)   # bdnzf cr0.so, end

    # Classic VMX
    t.emit(mtctr(21))
    t.emit(vnor(20, 21, 22))
    t.emit(vslh(20, 21, 22))
    t.emit(vsrh(20, 21, 22))
    t.emit(vspltish(20, -3))
    t.emit(vpkuwum(20, 21, 22))
    t.emit(vadduhs(20, 21, 22))
    t.emit(vsubuws(20, 21, 22))
    t.emit(vctuxs(20, 21, 4))
    t.emit(vctuxs(20, 21, 0))

    # VMX128 on the high register bank
    t.emit(vnor128(100, 101, 102))
    t.emit(vpkswss128(100, 101, 102))
    t.emit(vsel128(100, 101, 102))
    t.emit(vpkuwum128(100, 101, 102))

    t.mark('func_newinstrs_end')
    t.emit(blr())

    # --- jump table switch with case bodies past the .pdata end ---------------
    # Models the Sonic Generations shape: the .pdata entry stops at the default
    # blr while the compiler placed the case bodies right after it. The
    # recompiler must extend the function to cover them instead of erroring.
    t.mark('func_switch2')
    t.emit(cmplwi(6, 3, 3))
    bgt_default2 = t.here(); t.emit(0)       # placeholder: bgt default_case2
    lis_table2 = t.here(); t.emit(0)         # placeholder: lis r11, HI(table2)
    addi_table2 = t.here(); t.emit(0)        # placeholder: addi r11, r11, LO(table2)
    t.emit(rlwinm(0, 3, 2, 0, 25))           # same dispatch pattern as func_switch
    t.emit(lwzx(0, 11, 0))
    t.emit(mtctr(0))
    t.emit(bctr())
    t.mark('default_case2')
    default_case2 = t.here()
    t.emit(li(3, 0x2FF))
    t.emit(blr())
    t.mark('func_switch2_pdata_end')         # .pdata stops here...

    for i in range(4):                       # ...but the case bodies follow
        t.mark('case2_%d' % i)
        t.emit(li(3, 0x200 + i))
        t.emit(blr())

    t.mark('func_after_switch2')             # next function must stay intact
    t.emit(li(3, 0x400))
    t.emit(blr())
    t.mark('func_after_switch2_end')

    # --- resolve placeholders -------------------------------------------------
    words = t.words

    def index_of(addr):
        return (addr - IMAGE_BASE - TEXT_VA) // 4

    words[index_of(bdzf_at)] = bc_ctr(BO_BDZF, 2, bdzf_at, t.symbols['func_newinstrs_end'])
    words[index_of(bdzt_at)] = bc_ctr(BO_BDZT, 1, bdzt_at, t.symbols['func_newinstrs_end'])
    words[index_of(bdnzt_at)] = bc_ctr(BO_BDNZT, 0, bdnzt_at, t.symbols['func_newinstrs_end'])
    words[index_of(bdnzf_at)] = bc_ctr(BO_BDNZF, 3, bdnzf_at, t.symbols['func_newinstrs_end'])

    words[index_of(bl_main)] = b(bl_main, func_main, link=True)
    words[index_of(bl_helper)] = b(bl_helper, func_helper, link=True)
    words[index_of(bgt_back)] = bgt(bgt_back, loop_top, cr=6)
    words[index_of(bgt_default)] = bgt(bgt_default, default_case, cr=6)

    table_va = IMAGE_BASE + DATA_VA
    words[index_of(lis_table)] = lis(11, (table_va >> 16) & 0xFFFF)
    words[index_of(addi_table)] = addi(11, 11, table_va & 0xFFFF)

    words[index_of(bgt_default2)] = bgt(bgt_default2, default_case2, cr=6)

    table2_va = IMAGE_BASE + DATA_VA + 16    # second table follows the first
    words[index_of(lis_table2)] = lis(11, (table2_va >> 16) & 0xFFFF)
    words[index_of(addi_table2)] = addi(11, 11, table2_va & 0xFFFF)

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

    # .data: two jump tables (4 entries each) then padding
    jump_table = b''
    for i in range(4):
        jump_table += u32(t.symbols['case_%d' % i])
    jump_table2 = b''
    for i in range(4):
        jump_table2 += u32(t.symbols['case2_%d' % i])
    data = jump_table + jump_table2 + b'\0' * (0x800 - len(jump_table) - len(jump_table2))

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
    pdata += pdata_entry(t.symbols['func_newinstrs'],
                         (t.symbols['func_newinstrs_end'] + 4 - t.symbols['func_newinstrs']) // 4, 0)
    # func_switch2: .pdata stops at the default blr while the case bodies sit
    # past it (Sonic Generations shape); func_after_switch2 follows them.
    pdata += pdata_entry(t.symbols['func_switch2'],
                         (t.symbols['func_switch2_pdata_end'] - t.symbols['func_switch2']) // 4, 4)
    pdata += pdata_entry(t.symbols['func_after_switch2'],
                         (t.symbols['func_after_switch2_end'] - t.symbols['func_after_switch2']) // 4, 0)
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
