#include "crt_helpers.h"
#include "byteswap.h"
#include "section.h"

#include <cstring>

namespace
{
    // Raw big-endian instruction word field helpers.
    constexpr uint32_t Opcode(uint32_t insn) { return (insn >> 26) & 0x3F; }
    constexpr uint32_t RD(uint32_t insn) { return (insn >> 21) & 0x1F; }
    constexpr uint32_t RA(uint32_t insn) { return (insn >> 16) & 0x1F; }
    constexpr uint32_t RB(uint32_t insn) { return (insn >> 11) & 0x1F; }
    constexpr int32_t Simm(uint32_t insn) { return static_cast<int16_t>(insn & 0xFFFF); }
    constexpr int32_t DS(uint32_t insn) { return static_cast<int16_t>(insn & 0xFFFC); }

    // ld rT, d(rA) / std rT, d(rA)
    constexpr bool IsLd(uint32_t insn, uint32_t rt, uint32_t ra) { return Opcode(insn) == 58 && (insn & 3) == 0 && RD(insn) == rt && RA(insn) == ra; }
    constexpr bool IsStd(uint32_t insn, uint32_t rt, uint32_t ra) { return Opcode(insn) == 62 && (insn & 3) == 0 && RD(insn) == rt && RA(insn) == ra; }

    // lwz rT, d(rA) / stw rT, d(rA)
    constexpr bool IsLwz(uint32_t insn, uint32_t rt, uint32_t ra) { return Opcode(insn) == 32 && RD(insn) == rt && RA(insn) == ra; }
    constexpr bool IsStw(uint32_t insn, uint32_t rt, uint32_t ra) { return Opcode(insn) == 36 && RD(insn) == rt && RA(insn) == ra; }

    // lfd fT, d(rA) / stfd fT, d(rA) - rA is validated separately by the caller.
    constexpr bool IsLfd(uint32_t insn, uint32_t ft) { return Opcode(insn) == 50 && RD(insn) == ft; }
    constexpr bool IsStfd(uint32_t insn, uint32_t ft) { return Opcode(insn) == 54 && RD(insn) == ft; }

    // lvx vD, rA, rB (XO 103) / stvx vS, rA, rB (XO 231)
    constexpr uint32_t LVX_MATCH = 0x7C000000u | (103u << 1);
    constexpr uint32_t STVX_MATCH = 0x7C000000u | (231u << 1);
    constexpr bool IsLvx(uint32_t insn, uint32_t vd) { return (insn & 0xFC0007FFu) == LVX_MATCH && RD(insn) == vd; }
    constexpr bool IsStvx(uint32_t insn, uint32_t vs) { return (insn & 0xFC0007FFu) == STVX_MATCH && RD(insn) == vs; }

    // VMX128 lvx128 vD, rA, rB / stvx128 vS, rA, rB, used for registers v64 and above.
    // The 7-bit vector register field is split between bits 2-3 and bits 21-25.
    constexpr uint32_t LVX128_MATCH = 0x10000000u | 195u;
    constexpr uint32_t STVX128_MATCH = 0x10000000u | 451u;
    constexpr uint32_t VD128(uint32_t insn) { return ((insn << 3) & 0x60) | ((insn >> 21) & 0x1F); }
    constexpr bool IsLvx128(uint32_t insn, uint32_t vd) { return (insn & 0xFC0007F3u) == LVX128_MATCH && VD128(insn) == vd; }
    constexpr bool IsStvx128(uint32_t insn, uint32_t vs) { return (insn & 0xFC0007F3u) == STVX128_MATCH && VD128(insn) == vs; }

    // li rD, simm / addi rD, rA, simm - the setup instruction in front of every
    // lvx/stvx inside the VMX helper functions.
    constexpr bool IsAddi(uint32_t insn) { return Opcode(insn) == 14; }

    uint32_t WordAt(const uint8_t* data, size_t index)
    {
        uint32_t value;
        memcpy(&value, data + index * 4, sizeof(value));
        return ByteSwap(value);
    }

    // Detects a run of "count" D-form loads/stores with ascending register
    // numbers and displacement, e.g. ld r14, -0x98(r1) ... ld r31, -0x10(r1).
    template <typename MatchFn>
    bool DetectRegisterRun(const uint8_t* data, size_t wordCount, size_t i, uint32_t firstReg, uint32_t count, int32_t stride, MatchFn&& match)
    {
        if (i + count > wordCount)
            return false;

        if (!match(WordAt(data, i), firstReg))
            return false;

        int32_t displacement = match.displacement(WordAt(data, i));
        for (uint32_t k = 1; k < count; k++)
        {
            const uint32_t insn = WordAt(data, i + k);
            if (!match(insn, firstReg + k) || match.displacement(insn) != displacement + int32_t(k) * stride)
                return false;
        }

        return true;
    }

    struct GprLoadMatcher
    {
        bool ld64;
        uint32_t base;

        bool operator()(uint32_t insn, uint32_t rt) const
        {
            return ld64 ? IsLd(insn, rt, base) : IsLwz(insn, rt, base);
        }

        int32_t displacement(uint32_t insn) const
        {
            return ld64 ? DS(insn) : Simm(insn);
        }
    };

    struct GprStoreMatcher
    {
        bool st64;
        uint32_t base;

        bool operator()(uint32_t insn, uint32_t rt) const
        {
            return st64 ? IsStd(insn, rt, base) : IsStw(insn, rt, base);
        }

        int32_t displacement(uint32_t insn) const
        {
            return st64 ? DS(insn) : Simm(insn);
        }
    };

    struct FprLoadMatcher
    {
        uint32_t base;

        bool operator()(uint32_t insn, uint32_t ft) const
        {
            return IsLfd(insn, ft) && RA(insn) == base;
        }

        int32_t displacement(uint32_t insn) const
        {
            return Simm(insn);
        }
    };

    struct FprStoreMatcher
    {
        uint32_t base;

        bool operator()(uint32_t insn, uint32_t ft) const
        {
            return IsStfd(insn, ft) && RA(insn) == base;
        }

        int32_t displacement(uint32_t insn) const
        {
            return Simm(insn);
        }
    };

    // Detects the VMX helper pattern: (li ; lvx/stvx) pairs for ascending vector
    // registers. Returns the index of the setup instruction of the first pair.
    template <typename VectorMatchFn>
    bool DetectVectorPairRun(const uint8_t* data, size_t wordCount, size_t i, uint32_t firstReg, uint32_t count, VectorMatchFn&& match)
    {
        // The trigger instruction is the load/store of the first pair, the
        // function itself starts at the setup instruction before it.
        if (i < 1 || i - 1 + count * 2 > wordCount)
            return false;

        if (!match(WordAt(data, i), firstReg) || !IsAddi(WordAt(data, i - 1)))
            return false;

        const uint32_t ra = RA(WordAt(data, i));
        const uint32_t rb = RB(WordAt(data, i));

        for (uint32_t k = 1; k < count; k++)
        {
            const size_t pairIndex = i + size_t(k) * 2;
            const uint32_t insn = WordAt(data, pairIndex);
            if (!match(insn, firstReg + k) || RA(insn) != ra || RB(insn) != rb || !IsAddi(WordAt(data, pairIndex - 1)))
                return false;
        }

        return true;
    }

    struct VmxLowerMatcher
    {
        bool load;

        bool operator()(uint32_t insn, uint32_t vd) const
        {
            return load ? IsLvx(insn, vd) : IsStvx(insn, vd);
        }
    };

    struct VmxUpperMatcher
    {
        bool load;

        bool operator()(uint32_t insn, uint32_t vd) const
        {
            return load ? IsLvx128(insn, vd) : IsStvx128(insn, vd);
        }
    };
}

CrtHelperAddresses DetectCrtHelpers(const Image& image)
{
    CrtHelperAddresses result;

    for (const auto& section : image.sections)
    {
        if (!(section.flags & SectionFlags_Code))
            continue;

        const uint8_t* data = section.data;
        const size_t wordCount = section.size / 4;

        for (size_t i = 0; i < wordCount; i++)
        {
            const uint32_t insn = WordAt(data, i);
            const uint32_t address = static_cast<uint32_t>(section.base + i * 4);

            // __restgprlr_14: ld r14, D(r1) ... ld r31, D+0x88(r1)
            if (result.restGpr14 == 0 && (IsLd(insn, 14, 1) || IsLwz(insn, 14, 1)))
            {
                const bool ld64 = IsLd(insn, 14, 1);
                if (DetectRegisterRun(data, wordCount, i, 14, 18, ld64 ? 8 : 4, GprLoadMatcher{ ld64, 1 }))
                    result.restGpr14 = address;
            }

            // __savegprlr_14: std r14, D(r1) ... std r31, D+0x88(r1)
            if (result.saveGpr14 == 0 && (IsStd(insn, 14, 1) || IsStw(insn, 14, 1)))
            {
                const bool st64 = IsStd(insn, 14, 1);
                if (DetectRegisterRun(data, wordCount, i, 14, 18, st64 ? 8 : 4, GprStoreMatcher{ st64, 1 }))
                    result.saveGpr14 = address;
            }

            // __restfpr_14: lfd f14, D(rA) ... lfd f31, D+0x88(rA)
            if (result.restFpr14 == 0 && IsLfd(insn, 14))
            {
                if (DetectRegisterRun(data, wordCount, i, 14, 18, 8, FprLoadMatcher{ RA(insn) }))
                    result.restFpr14 = address;
            }

            // __savefpr_14: stfd f14, D(rA) ... stfd f31, D+0x88(rA)
            if (result.saveFpr14 == 0 && IsStfd(insn, 14))
            {
                if (DetectRegisterRun(data, wordCount, i, 14, 18, 8, FprStoreMatcher{ RA(insn) }))
                    result.saveFpr14 = address;
            }

            // __restvmx_14: (li ; lvx v14) ... (li ; lvx v31)
            if (result.restVmx14 == 0 && IsLvx(insn, 14))
            {
                if (DetectVectorPairRun(data, wordCount, i, 14, 18, VmxLowerMatcher{ true }))
                    result.restVmx14 = address - 4;
            }

            // __savevmx_14: (li ; stvx v14) ... (li ; stvx v31)
            if (result.saveVmx14 == 0 && IsStvx(insn, 14))
            {
                if (DetectVectorPairRun(data, wordCount, i, 14, 18, VmxLowerMatcher{ false }))
                    result.saveVmx14 = address - 4;
            }

            // __restvmx_64: (li ; lvx128 v64) ... (li ; lvx128 v127)
            if (result.restVmx64 == 0 && IsLvx128(insn, 64))
            {
                if (DetectVectorPairRun(data, wordCount, i, 64, 64, VmxUpperMatcher{ true }))
                    result.restVmx64 = address - 4;
            }

            // __savevmx_64: (li ; stvx128 v64) ... (li ; stvx128 v127)
            if (result.saveVmx64 == 0 && IsStvx128(insn, 64))
            {
                if (DetectVectorPairRun(data, wordCount, i, 64, 64, VmxUpperMatcher{ false }))
                    result.saveVmx64 = address - 4;
            }

            // Early exit once everything has been found.
            if (result.restGpr14 != 0 && result.saveGpr14 != 0 && result.restFpr14 != 0 && result.saveFpr14 != 0 &&
                result.restVmx14 != 0 && result.saveVmx14 != 0 && result.restVmx64 != 0 && result.saveVmx64 != 0)
            {
                return result;
            }
        }
    }

    return result;
}
