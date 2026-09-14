#include "xex.h"
#include "image.h"
#include <cassert>
#include <cstring>
#include <new>
#include <vector>
#include <unordered_map>
#include <aes.hpp>
#include <fmt/core.h>
#include <TinySHA1.hpp>
#include <xex_patcher.h>

#define STRINGIFY(X) #X
#define XE_EXPORT(MODULE, ORDINAL, NAME, TYPE) { (ORDINAL), "__imp__" STRINGIFY(NAME) }

#ifndef _WIN32

typedef struct _IMAGE_DOS_HEADER { 
    uint16_t   e_magic;                
    uint16_t   e_cblp;                 
    uint16_t   e_cp;                   
    uint16_t   e_crlc;                 
    uint16_t   e_cparhdr;              
    uint16_t   e_minalloc;             
    uint16_t   e_maxalloc;             
    uint16_t   e_ss;                   
    uint16_t   e_sp;                   
    uint16_t   e_csum;                 
    uint16_t   e_ip;                   
    uint16_t   e_cs;                   
    uint16_t   e_lfarlc;               
    uint16_t   e_ovno;                 
    uint16_t   e_res[4];               
    uint16_t   e_oemid;                
    uint16_t   e_oeminfo;              
    uint16_t   e_res2[10];             
    uint32_t   e_lfanew;               
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    uint16_t   Machine;
    uint16_t   NumberOfSections;
    uint32_t   TimeDateStamp;
    uint32_t   PointerToSymbolTable;
    uint32_t   NumberOfSymbols;
    uint16_t   SizeOfOptionalHeader;
    uint16_t   Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t   VirtualAddress;
    uint32_t   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
    uint16_t   Magic;
    uint8_t    MajorLinkerVersion;
    uint8_t    MinorLinkerVersion;
    uint32_t   SizeOfCode;
    uint32_t   SizeOfInitializedData;
    uint32_t   SizeOfUninitializedData;
    uint32_t   AddressOfEntryPoint;
    uint32_t   BaseOfCode;
    uint32_t   BaseOfData;
    uint32_t   ImageBase;
    uint32_t   SectionAlignment;
    uint32_t   FileAlignment;
    uint16_t   MajorOperatingSystemVersion;
    uint16_t   MinorOperatingSystemVersion;
    uint16_t   MajorImageVersion;
    uint16_t   MinorImageVersion;
    uint16_t   MajorSubsystemVersion;
    uint16_t   MinorSubsystemVersion;
    uint32_t   Win32VersionValue;
    uint32_t   SizeOfImage;
    uint32_t   SizeOfHeaders;
    uint32_t   CheckSum;
    uint16_t   Subsystem;
    uint16_t   DllCharacteristics;
    uint32_t   SizeOfStackReserve;
    uint32_t   SizeOfStackCommit;
    uint32_t   SizeOfHeapReserve;
    uint32_t   SizeOfHeapCommit;
    uint32_t   LoaderFlags;
    uint32_t   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    uint8_t    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32_t   PhysicalAddress;
        uint32_t   VirtualSize;
    } Misc;
    uint32_t   VirtualAddress;
    uint32_t   SizeOfRawData;
    uint32_t   PointerToRawData;
    uint32_t   PointerToRelocations;
    uint32_t   PointerToLinenumbers;
    uint16_t   NumberOfRelocations;
    uint16_t   NumberOfLinenumbers;
    uint32_t   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

#define IMAGE_SCN_CNT_CODE                   0x00000020

#endif

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE    0x5A4D      // MZ
#endif

#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE     0x00004550  // PE00
#endif

std::unordered_map<size_t, const char*> XamExports = 
{
    #include "xbox/xam_table.inc"
};

std::unordered_map<size_t, const char*> XboxKernelExports =
{
    #include "xbox/xboxkrnl_table.inc"
};

Image Xex2LoadImage(const uint8_t* data, size_t dataSize)
{
    // The Xbox 360 has 512 MB of RAM, an image larger than this is guaranteed
    // to be the result of a corrupt header (or an unsupported file) and would
    // previously blow up with std::bad_alloc.
    constexpr size_t MaxImageSize = 1ull * 1024 * 1024 * 1024;

    if (data == nullptr || dataSize < sizeof(Xex2Header))
    {
        fmt::println("ERROR: File is too small to be a valid XEX2 executable.");
        return {};
    }

    auto* header = reinterpret_cast<const Xex2Header*>(data);

    const uint32_t headerSize = header->headerSize;
    const uint32_t securityOffset = header->securityOffset;

    if (headerSize > dataSize || headerSize < sizeof(Xex2Header))
    {
        fmt::println("ERROR: XEX2 header size (0x{:X}) is out of bounds for a file of size 0x{:X}. The file may be truncated or corrupt.", headerSize, dataSize);
        return {};
    }

    if (securityOffset > dataSize || dataSize - securityOffset < sizeof(Xex2SecurityInfo))
    {
        fmt::println("ERROR: XEX2 security info offset (0x{:X}) is out of bounds. The file may be truncated or corrupt.", securityOffset);
        return {};
    }

    if (24 + size_t(header->headerCount.get()) * sizeof(Xex2OptHeader) > headerSize)
    {
        fmt::println("ERROR: XEX2 optional header count ({}) is out of bounds. The file may be corrupt.", header->headerCount.get());
        return {};
    }

    auto* security = reinterpret_cast<const Xex2SecurityInfo*>(data + securityOffset);
    const auto* fileFormatInfo = reinterpret_cast<const Xex2OptFileFormatInfo*>(getOptHeaderPtr(data, XEX_HEADER_FILE_FORMAT_INFO));

    Image image{};
    std::unique_ptr<uint8_t[]> result{};
    size_t imageSize = security->imageSize;

    if (imageSize == 0 || imageSize > MaxImageSize)
    {
        fmt::println("ERROR: XEX2 image size (0x{:X}) reported by the security info is invalid. The file may be corrupt or unsupported.", imageSize);
        return {};
    }

    // Helper that reports allocation failures instead of terminating with std::bad_alloc.
    auto allocImageBuffer = [](size_t size) -> std::unique_ptr<uint8_t[]>
    {
        try
        {
            return std::make_unique<uint8_t[]>(size);
        }
        catch (const std::bad_alloc&)
        {
            fmt::println("ERROR: Failed to allocate {} bytes of memory. Not enough memory available to process this XEX file.", size);
            return {};
        }
    };

    // Decompress image
    if (fileFormatInfo != nullptr)
    {
        const uint16_t compressionType = fileFormatInfo->compressionType;
        if (compressionType > XEX_COMPRESSION_NORMAL)
        {
            fmt::println("ERROR: Delta-compressed XEX files (title update patches) cannot be recompiled directly. Pass the base XEX together with the patch through the config file instead.");
            return {};
        }

        std::unique_ptr<uint8_t[]> decryptedData;
        const uint8_t* srcData = nullptr;
        const size_t exeFileSize = dataSize - headerSize;

        if (fileFormatInfo->encryptionType == XEX_ENCRYPTION_NORMAL)
        {
            constexpr uint32_t KeySize = 16;
            AES_ctx aesContext;

            uint8_t decryptedKey[KeySize];
            memcpy(decryptedKey, security->aesKey, KeySize);
            AES_init_ctx_iv(&aesContext, Xex2RetailKey, AESBlankIV);
            AES_CBC_decrypt_buffer(&aesContext, decryptedKey, KeySize);

            decryptedData = allocImageBuffer(exeFileSize);
            if (decryptedData == nullptr)
                return {};

            memcpy(decryptedData.get(), data + headerSize, exeFileSize);
            AES_init_ctx_iv(&aesContext, decryptedKey, AESBlankIV);
            AES_CBC_decrypt_buffer(&aesContext, decryptedData.get(), exeFileSize);

            srcData = decryptedData.get();
        }
        else if (fileFormatInfo->encryptionType == XEX_ENCRYPTION_NONE)
        {
            srcData = data + headerSize;
        }
        else
        {
            fmt::println("ERROR: Unknown XEX2 encryption type ({}).", static_cast<uint16_t>(fileFormatInfo->encryptionType));
            return {};
        }

        if (compressionType == XEX_COMPRESSION_NONE)
        {
            if (imageSize > exeFileSize)
            {
                fmt::println("ERROR: XEX2 image size (0x{:X}) is larger than the data available in the file (0x{:X}). The file may be truncated or corrupt.", imageSize, exeFileSize);
                return {};
            }

            result = allocImageBuffer(imageSize);
            if (result == nullptr)
                return {};

            memcpy(result.get(), srcData, imageSize);
        }
        else if (compressionType == XEX_COMPRESSION_BASIC)
        {
            if (fileFormatInfo->infoSize < sizeof(Xex2FileBasicCompressionInfo) * 2)
            {
                fmt::println("ERROR: XEX2 basic compression info size (0x{:X}) is invalid.", static_cast<uint32_t>(fileFormatInfo->infoSize));
                return {};
            }

            auto* blocks = reinterpret_cast<const Xex2FileBasicCompressionBlock*>(fileFormatInfo + 1);
            const size_t numBlocks = (fileFormatInfo->infoSize / sizeof(Xex2FileBasicCompressionInfo)) - 1;

            if (reinterpret_cast<const uint8_t*>(blocks) + numBlocks * sizeof(Xex2FileBasicCompressionBlock) > data + dataSize)
            {
                fmt::println("ERROR: XEX2 basic compression blocks are out of bounds. The file may be corrupt.");
                return {};
            }

            imageSize = 0;
            size_t compressedSize = 0;
            for (size_t i = 0; i < numBlocks; i++)
            {
                imageSize += blocks[i].dataSize + blocks[i].zeroSize;
                compressedSize += blocks[i].dataSize;
            }

            if (imageSize == 0 || imageSize > MaxImageSize)
            {
                fmt::println("ERROR: XEX2 basic compression blocks describe an invalid image size (0x{:X}).", imageSize);
                return {};
            }

            if (compressedSize > exeFileSize)
            {
                fmt::println("ERROR: XEX2 basic compression blocks require 0x{:X} bytes of data, but the file only contains 0x{:X}. The file may be truncated or corrupt.", compressedSize, exeFileSize);
                return {};
            }

            result = allocImageBuffer(imageSize);
            if (result == nullptr)
                return {};

            auto* destData = result.get();

            for (size_t i = 0; i < numBlocks; i++)
            {
                memcpy(destData, srcData, blocks[i].dataSize);

                srcData += blocks[i].dataSize;
                destData += blocks[i].dataSize;

                memset(destData, 0, blocks[i].zeroSize);
                destData += blocks[i].zeroSize;
            }
        }
        else if (compressionType == XEX_COMPRESSION_NORMAL)
        {
            result = allocImageBuffer(imageSize);
            if (result == nullptr)
                return {};

            auto* destData = result.get();

            const Xex2FileNormalCompressionInfo* normalInfo = (const Xex2FileNormalCompressionInfo*)(fileFormatInfo + 1);
            if (reinterpret_cast<const uint8_t*>(normalInfo) + sizeof(Xex2FileNormalCompressionInfo) > data + dataSize)
            {
                fmt::println("ERROR: XEX2 LZX compression info is out of bounds. The file may be corrupt.");
                return {};
            }

            const Xex2CompressedBlockInfo* blocks = &normalInfo->firstBlock;

            const uint32_t exeLength = static_cast<uint32_t>(exeFileSize);
            const uint8_t* exeBuffer = srcData;

            auto compressBuffer = allocImageBuffer(exeLength);
            if (compressBuffer == nullptr)
                return {};

            const uint8_t* p = NULL;
            uint8_t* d = NULL;
            sha1::SHA1 s;

            p = exeBuffer;
            d = compressBuffer.get();

            uint8_t blockCalcedDigest[0x14];
            const uint8_t* exeEnd = srcData + exeLength;
            while (blocks->blockSize) 
            {
                if (blocks->blockSize.get() < sizeof(Xex2CompressedBlockInfo) || p < srcData || p + blocks->blockSize.get() > exeEnd)
                {
                    fmt::println("ERROR: XEX2 compressed block at offset 0x{:X} is out of bounds. The file may be truncated or corrupt.", static_cast<size_t>(p - srcData));
                    return {};
                }

                const uint8_t* pNext = p + blocks->blockSize;
                const auto* nextBlock = (const Xex2CompressedBlockInfo*)p;

                s.reset();
                s.processBytes(p, blocks->blockSize);
                s.finalize(blockCalcedDigest);

                if (memcmp(blockCalcedDigest, blocks->blockHash, 0x14) != 0)
                {
                    fmt::println("ERROR: XEX2 block hash mismatch, the file may be corrupt.");
                    return {};
                }

                p += 4;
                p += 20;

                while (true) 
                {
                    const size_t chunkSize = (p[0] << 8) | p[1];
                    p += 2;

                    if (!chunkSize)
                        break;

                    memcpy(d, p, chunkSize);
                    p += chunkSize;
                    d += chunkSize;
                }

                p = pNext;
                blocks = nextBlock;
            }

            int resultCode = 0;
            uint32_t uncompressedSize = security->imageSize;
            uint8_t* buffer = destData;

            resultCode = lzxDecompress(compressBuffer.get(), d - compressBuffer.get(), buffer, uncompressedSize, ((const Xex2FileNormalCompressionInfo*)(fileFormatInfo + 1))->windowSize, nullptr, 0);

            if (resultCode)
            {
                fmt::println("ERROR: LZX decompression of the XEX2 file failed (code {}). The file may be corrupt.", resultCode);
                return {};
            }
        }
    }

    if (result == nullptr)
    {
        fmt::println("ERROR: XEX2 file does not contain a supported file format info header.");
        return {};
    }

    image.data = std::move(result);
    image.size = security->imageSize;

    // Map image
    const auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data.get());
    if (image.size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32) || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        fmt::println("ERROR: XEX2 image does not contain a valid executable header. The file may be corrupt or use an unsupported encryption scheme.");
        return {};
    }

    if (dosHeader->e_lfanew >= image.size - sizeof(IMAGE_NT_HEADERS32))
    {
        fmt::println("ERROR: XEX2 image PE header offset (0x{:X}) is out of bounds.", dosHeader->e_lfanew);
        return {};
    }

    const auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS32*>(image.data.get() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        fmt::println("ERROR: XEX2 image does not contain a valid PE signature. The file may be corrupt.");
        return {};
    }

    image.base = security->loadAddress;
    const void* xex2BaseAddressPtr = getOptHeaderPtr(data, XEX_HEADER_IMAGE_BASE_ADDRESS);
    if (xex2BaseAddressPtr != nullptr)
    {
        image.base = *reinterpret_cast<const be<uint32_t>*>(xex2BaseAddressPtr);
    }
    const void* xex2EntryPointPtr = getOptHeaderPtr(data, XEX_HEADER_ENTRY_POINT);
    if (xex2EntryPointPtr != nullptr)
    {
        image.entry_point = *reinterpret_cast<const be<uint32_t>*>(xex2EntryPointPtr);
    }

    const auto numSections = ntHeaders->FileHeader.NumberOfSections;
    if (numSections == 0 || numSections > 96)
    {
        fmt::println("ERROR: XEX2 image reports an invalid section count ({}). The file may be corrupt.", numSections);
        return {};
    }

    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(ntHeaders + 1);
    const size_t sectionsEnd = dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + size_t(numSections) * sizeof(IMAGE_SECTION_HEADER);
    if (sectionsEnd > image.size)
    {
        fmt::println("ERROR: XEX2 image section headers are out of bounds. The file may be corrupt.");
        return {};
    }

    for (size_t i = 0; i < numSections; i++)
    {
        const auto& section = sections[i];
        uint8_t flags{};

        if (section.Characteristics & IMAGE_SCN_CNT_CODE)
        {
            flags |= SectionFlags_Code;
        }

        if (section.VirtualAddress >= image.size || section.Misc.VirtualSize > image.size - section.VirtualAddress)
        {
            fmt::println("ERROR: XEX2 image section {} is out of bounds. The file may be corrupt.", reinterpret_cast<const char*>(section.Name));
            return {};
        }

        image.Map(reinterpret_cast<const char*>(section.Name), section.VirtualAddress, 
            section.Misc.VirtualSize, flags, image.data.get() + section.VirtualAddress);
    }

    auto* imports = reinterpret_cast<const Xex2ImportHeader*>(getOptHeaderPtr(data, XEX_HEADER_IMPORT_LIBRARIES));
    if (imports != nullptr)
    {
        std::vector<std::string_view> stringTable;
        auto* pStrTable = reinterpret_cast<const char*>(imports + 1);

        size_t paddedStringOffset = 0;
        for (size_t i = 0; i < imports->numImports; i++)
        {
            stringTable.emplace_back(pStrTable + paddedStringOffset);
            
            // pad the offset to the next multiple of 4
            paddedStringOffset += ((stringTable.back().length() + 1) + 3) & ~3;
        }

        auto* library = (Xex2ImportLibrary*)(((char*)imports) + sizeof(Xex2ImportHeader) + imports->sizeOfStringTable);
        for (size_t i = 0; i < stringTable.size(); i++)
        {
            auto* descriptors = (Xex2ImportDescriptor*)(library + 1);
            static std::unordered_map<size_t, const char*> DummyExports;
            const std::unordered_map<size_t, const char*>* names = &DummyExports;

            if (stringTable[i] == "xam.xex")
            {
                names = &XamExports;
            }
            else if (stringTable[i] == "xboxkrnl.exe")
            {
                names = &XboxKernelExports;
            }

            for (size_t im = 0; im < library->numberOfImports; im++)
            {
                auto originalThunk = (Xex2ThunkData*)image.Find(descriptors[im].firstThunk);
                if (originalThunk == nullptr)
                {
                    fmt::println("WARNING: Import thunk at 0x{:X} is not mapped in the image, skipping.", static_cast<uint32_t>(descriptors[im].firstThunk));
                    continue;
                }

                auto originalData = originalThunk;
                originalData->data = ByteSwap(originalData->data);

                if (originalData->originalData.type != 0)
                {
                    uint32_t thunk[4] = { 0x00000060, 0x00000060, 0x00000060, 0x2000804E };
                    auto name = names->find(originalData->originalData.ordinal);
                    if (name != names->end())
                    {
                        image.symbols.insert({ name->second, descriptors[im].firstThunk, sizeof(thunk), Symbol_Function });
                    }

                    memcpy(originalThunk, thunk, sizeof(thunk));
                }
            }
            library = (Xex2ImportLibrary*)((char*)(library + 1) + library->numberOfImports * sizeof(Xex2ImportDescriptor));
        }
    }

    return image;
}
