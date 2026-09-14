#pragma once

#include <filesystem>
#include <fstream>
#include <new>
#include <vector>

inline std::vector<uint8_t> LoadFile(const std::filesystem::path& path)
{
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec))
    {
        return {};
    }

    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open())
    {
        return {};
    }

    stream.seekg(0, std::ios::end);
    std::streampos size = stream.tellg();
    stream.seekg(0, std::ios::beg);

    // A failed seek/tell leaves the stream in a bad state and would return -1,
    // which used to be resized into a gigantic allocation (std::bad_alloc).
    if (stream.fail() || size <= 0)
    {
        return {};
    }

    std::vector<uint8_t> data;
    try
    {
        data.resize(static_cast<size_t>(size));
    }
    catch (const std::bad_alloc&)
    {
        return {};
    }

    stream.read(reinterpret_cast<char*>(data.data()), size);
    if (stream.bad() || stream.gcount() != static_cast<std::streamsize>(size))
    {
        return {};
    }

    return data;
}
