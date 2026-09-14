#include <algorithm>
#include <cassert>
#include <iterator>
#include <file.h>
#include <disasm.h>
#include <image.h>
#include <xbox.h>
#include <fmt/core.h>
#include "function.h"

#define SWITCH_ABSOLUTE 0
#define SWITCH_COMPUTED 1
#define SWITCH_BYTEOFFSET 2
#define SWITCH_SHORTOFFSET 3

struct SwitchTable
{
    std::vector<size_t> labels{};
    size_t base{};
    size_t defaultLabel{};
    uint32_t r{};
    uint32_t type{};
};

// Helper that safely disassembles one instruction at a virtual address.
// Returns false if the address is not mapped or the instruction is invalid,
// both of which used to crash here through null pointer dereferences.
static bool SafeDisassemble(Image& image, size_t address, ppc_insn& insn)
{
    const auto* ptr = (uint32_t*)image.Find(address);
    if (ptr == nullptr)
        return false;

    ppc::Disassemble(ptr, address, insn);
    return insn.opcode != nullptr;
}

// Validates that [address, address + byteCount) is fully mapped in the image.
static bool IsRegionMapped(Image& image, size_t address, size_t byteCount)
{
    const Section* section = image.FindSection(address);
    return section != nullptr && address + byteCount <= section->base + section->size;
}

bool ReadTable(Image& image, SwitchTable& table)
{
    if (table.labels.empty())
        return false;

    uint32_t pOffset;
    ppc_insn insn;

    // All variants read up to six words starting at the table base.
    if (!IsRegionMapped(image, table.base, 24))
        return false;

    if (!SafeDisassemble(image, table.base, insn))
        return false;

    pOffset = insn.operands[1] << 16;

    if (!SafeDisassemble(image, table.base + 4, insn))
        return false;

    pOffset += insn.operands[2];

    if (table.type == SWITCH_ABSOLUTE)
    {
        if (!IsRegionMapped(image, pOffset, table.labels.size() * sizeof(uint32_t)))
            return false;

        const auto* offsets = (be<uint32_t>*)image.Find(pOffset);
        for (size_t i = 0; i < table.labels.size(); i++)
        {
            table.labels[i] = offsets[i];
        }
    }
    else if (table.type == SWITCH_COMPUTED)
    {
        if (!IsRegionMapped(image, pOffset, table.labels.size() * sizeof(uint8_t)))
            return false;

        uint32_t base;
        uint32_t shift;
        const auto* offsets = (uint8_t*)image.Find(pOffset);

        if (!SafeDisassemble(image, table.base + 0x10, insn))
            return false;

        base = insn.operands[1] << 16;

        if (!SafeDisassemble(image, table.base + 0x14, insn))
            return false;

        base += insn.operands[2];

        if (!SafeDisassemble(image, table.base + 0x0C, insn))
            return false;

        shift = insn.operands[2];

        // A shift that large can only come from misdetected data.
        if (shift > 24)
            return false;

        for (size_t i = 0; i < table.labels.size(); i++)
        {
            table.labels[i] = base + (offsets[i] << shift);
        }
    }
    else if (table.type == SWITCH_BYTEOFFSET || table.type == SWITCH_SHORTOFFSET)
    {
        if (table.type == SWITCH_BYTEOFFSET)
        {
            if (!IsRegionMapped(image, pOffset, table.labels.size() * sizeof(uint8_t)))
                return false;

            const auto* offsets = (uint8_t*)image.Find(pOffset);
            uint32_t base;

            if (!SafeDisassemble(image, table.base + 0x0C, insn))
                return false;

            base = insn.operands[1] << 16;

            if (!SafeDisassemble(image, table.base + 0x10, insn))
                return false;

            base += insn.operands[2];

            for (size_t i = 0; i < table.labels.size(); i++)
            {
                table.labels[i] = base + offsets[i];
            }
        }
        else if (table.type == SWITCH_SHORTOFFSET)
        {
            if (!IsRegionMapped(image, pOffset, table.labels.size() * sizeof(uint16_t)))
                return false;

            const auto* offsets = (be<uint16_t>*)image.Find(pOffset);
            uint32_t base;

            if (!SafeDisassemble(image, table.base + 0x10, insn))
                return false;

            base = insn.operands[1] << 16;

            if (!SafeDisassemble(image, table.base + 0x14, insn))
                return false;

            base += insn.operands[2];

            for (size_t i = 0; i < table.labels.size(); i++)
            {
                table.labels[i] = base + offsets[i];
            }
        }
    }
    else
    {
        assert(false);
        return false;
    }

    return true;
}

void ScanTable(const uint32_t* code, size_t base, SwitchTable& table, size_t wordsBack)
{
    ppc_insn insn;
    uint32_t cr{ (uint32_t)-1 };

    // Never scan further back than the start of the section. Matches near the
    // very beginning used to make code[-i] read out of bounds.
    const int count = (int)std::min<size_t>(32, wordsBack);
    for (int i = 0; i < count; i++)
    {
        ppc::Disassemble(&code[-i], base - (4 * i), insn);
        if (insn.opcode == nullptr)
        {
            continue;
        }

        if (cr == -1 && (insn.opcode->id == PPC_INST_BGT || insn.opcode->id == PPC_INST_BGTLR || insn.opcode->id == PPC_INST_BLE || insn.opcode->id == PPC_INST_BLELR))
        {
            cr = insn.operands[0];
            if (insn.opcode->operands[1] != 0)
            {
                table.defaultLabel = insn.operands[1];
            }
        }
        else if (cr != -1)
        {
            if (insn.opcode->id == PPC_INST_CMPLWI && insn.operands[0] == cr)
            {
                table.r = insn.operands[1];
                table.labels.resize(insn.operands[2] + 1);
                table.base = base;
                break;
            }
        }
    }
}

void MakeMask(const uint32_t* instructions, size_t count)
{
    ppc_insn insn;
    for (size_t i = 0; i < count; i++)
    {
        ppc::Disassemble(&instructions[i], 0, insn);
        fmt::println("0x{:X}, // {}", ByteSwap(insn.opcode->opcode | (insn.instruction & insn.opcode->mask)), insn.opcode->name);
    }
}

void* SearchMask(const void* source, const uint32_t* compare, size_t compareCount, size_t size)
{
    assert(size % 4 == 0);
    uint32_t* src = (uint32_t*)source;
    size_t count = size / 4;
    ppc_insn insn;

    for (size_t i = 0; i < count; i++)
    {
        size_t c = 0;
        for (c = 0; c < compareCount; c++)
        {
            if (i + c >= count)
            {
                break;
            }

            ppc::Disassemble(&src[i + c], 0, insn);
            if (insn.opcode == nullptr || insn.opcode->id != compare[c])
            {
                break;
            }
        }

        if (c == compareCount)
        {
            return &src[i];
        }
    }

    return nullptr;
}

static std::string out;

template<class... Args>
static void println(fmt::format_string<Args...> fmt, Args&&... args)
{
    fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
    out += '\n';
};

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("Usage: XenonAnalyse [input XEX file path] [output jump table TOML file path]");
        return EXIT_SUCCESS;
    }

    const auto file = LoadFile(argv[1]);
    if (file.empty())
    {
        fprintf(stderr, "ERROR: Unable to load the file '%s', make sure it exists.\n", argv[1]);
        return EXIT_FAILURE;
    }

    auto image = Image::ParseImage(file.data(), file.size());
    if (image.data == nullptr || image.sections.empty())
    {
        fprintf(stderr, "ERROR: Unable to parse '%s', no image sections were loaded. The file must be a decrypted XEX2 or ELF executable.\n", argv[1]);
        return EXIT_FAILURE;
    }

    auto printTable = [&](const SwitchTable& table)
        {
            println("[[switch]]");
            println("base = 0x{:X}", table.base);
            println("r = {}", table.r);
            println("default = 0x{:X}", table.defaultLabel);
            println("labels = [");
            for (const auto& label : table.labels)
            {
                println("    0x{:X},", label);
            }

            println("]");
            println("");
        };

    std::vector<SwitchTable> switches{};

    println("# Generated by XenonAnalyse");

    auto scanPattern = [&](uint32_t* pattern, size_t count, size_t type)
        {
            for (const auto& section : image.sections)
            {
                if (!(section.flags & SectionFlags_Code))
                {
                    continue;
                }

                size_t base = section.base;
                uint8_t* data = section.data;
                uint8_t* dataStart = section.data;
                uint8_t* dataEnd = section.data + section.size;
                while (data < dataEnd && data != nullptr)
                {
                    data = (uint8_t*)SearchMask(data, pattern, count, dataEnd - data);

                    if (data != nullptr)
                    {
                        SwitchTable table{};
                        table.type = type;
                        ScanTable((uint32_t*)data, base + (data - dataStart), table, (data - dataStart) / 4);

                        // fmt::println("{:X} ; jmptable - {}", base + (data - dataStart), table.labels.size());
                        if (table.base != 0)
                        {
                            if (ReadTable(image, table))
                            {
                                printTable(table);
                                switches.emplace_back(std::move(table));
                            }
                            else
                            {
                                fmt::println("WARNING: Ignoring a jump table candidate at 0x{:X}, its table data is not mapped in the image.", table.base);
                            }
                        }

                        data += 4;
                    }
                    continue;
                }
            }
        };

    uint32_t absoluteSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_RLWINM,
        PPC_INST_LWZX,
        PPC_INST_MTCTR,
        PPC_INST_BCTR,
    };

    uint32_t computedSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_LBZX,
        PPC_INST_RLWINM,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    uint32_t offsetSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_LBZX,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    uint32_t wordOffsetSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_RLWINM,
        PPC_INST_LHZX,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    println("# ---- ABSOLUTE JUMPTABLE ----");
    scanPattern(absoluteSwitch, std::size(absoluteSwitch), SWITCH_ABSOLUTE);

    println("# ---- COMPUTED JUMPTABLE ----");
    scanPattern(computedSwitch, std::size(computedSwitch), SWITCH_COMPUTED);

    println("# ---- OFFSETED JUMPTABLE ----");
    scanPattern(offsetSwitch, std::size(offsetSwitch), SWITCH_BYTEOFFSET);
    scanPattern(wordOffsetSwitch, std::size(wordOffsetSwitch), SWITCH_SHORTOFFSET);

    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(argv[2]).parent_path(), ec);

    std::ofstream f(argv[2]);
    if (!f.is_open())
    {
        fprintf(stderr, "ERROR: Unable to open '%s' for writing.\n", argv[2]);
        return EXIT_FAILURE;
    }

    f.write(out.data(), out.size());

    fmt::println("Found {} jump table(s), written to '{}'.", switches.size(), argv[2]);

    return EXIT_SUCCESS;
}
