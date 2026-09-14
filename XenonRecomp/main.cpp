#include "pch.h"
#include "test_recompiler.h"

int main(int argc, char* argv[])
{
    try
    {
#ifndef XENON_RECOMP_CONFIG_FILE_PATH
        if (argc < 3)
        {
            printf("Usage: XenonRecomp [input TOML file path] [PPC context header file path]\n");
            return EXIT_SUCCESS;
        }
#endif

        const char* path = 
        #ifdef XENON_RECOMP_CONFIG_FILE_PATH
            XENON_RECOMP_CONFIG_FILE_PATH
        #else
            argv[1]
        #endif
            ;

        std::error_code ec;
        if (std::filesystem::is_regular_file(path, ec))
        {
            Recompiler recompiler;
            if (!recompiler.LoadConfig(path))
                return EXIT_FAILURE;

            recompiler.Analyse();

            auto entry = recompiler.image.symbols.find(recompiler.image.entry_point);
            if (entry != recompiler.image.symbols.end())
            {
                entry->name = "_xstart";
            }

            const char* headerFilePath =
#ifdef XENON_RECOMP_HEADER_FILE_PATH
            XENON_RECOMP_HEADER_FILE_PATH
#else
            argv[2]
#endif
                ;

#ifndef XENON_RECOMP_HEADER_FILE_PATH
            if (headerFilePath == nullptr)
            {
                printf("ERROR: No PPC context header file path was provided.\n");
                return EXIT_FAILURE;
            }
#endif

            recompiler.Recompile(headerFilePath);
        }
        else
        {
            if (argc < 3)
            {
                printf("ERROR: '%s' is not a regular file. Pass a TOML configuration file, or a test directory together with a destination directory.\n", path);
                return EXIT_FAILURE;
            }

            TestRecompiler::RecompileTests(path, argv[2]);
        }

        return EXIT_SUCCESS;
    }
    catch (const std::bad_alloc&)
    {
        fmt::println("ERROR: Ran out of memory while recompiling (std::bad_alloc).");
        fmt::println("       This usually means the executable could not be parsed correctly.");
        fmt::println("       Verify that the XEX file is decrypted and that the addresses in the TOML file are correct.");
        return EXIT_FAILURE;
    }
    catch (const std::exception& e)
    {
        fmt::println("ERROR: {}", e.what());
        return EXIT_FAILURE;
    }
}
