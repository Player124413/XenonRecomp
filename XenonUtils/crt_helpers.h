#pragma once

#include <cstdint>
#include "image.h"

// Start addresses of the CRT register save/restore helper functions that the
// recompiler needs in order to model their switch-case-like fallthrough entries.
// These follow the standard Xbox 360 CRT implementations, which are essentially
// identical between games, making them detectable through their instruction
// patterns.
struct CrtHelperAddresses
{
    uint32_t restGpr14 = 0;
    uint32_t saveGpr14 = 0;
    uint32_t restFpr14 = 0;
    uint32_t saveFpr14 = 0;
    uint32_t restVmx14 = 0;
    uint32_t saveVmx14 = 0;
    uint32_t restVmx64 = 0;
    uint32_t saveVmx64 = 0;
};

// Scans the code sections of the image for the CRT helpers. Addresses that
// cannot be found are left at zero.
CrtHelperAddresses DetectCrtHelpers(const Image& image);
