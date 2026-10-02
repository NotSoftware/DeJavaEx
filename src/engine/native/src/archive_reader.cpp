/*
MIT License

Copyright (c) 2026 DeJavaEx

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "dejavaex/analysis.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dejavaex {

namespace {

std::uint16_t read16(const std::vector<unsigned char>& bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(bytes[offset])
        | static_cast<std::uint16_t>(bytes[offset + 1]) << 8;
}

std::uint32_t read32(const std::vector<unsigned char>& bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset])
        | static_cast<std::uint32_t>(bytes[offset + 1]) << 8
        | static_cast<std::uint32_t>(bytes[offset + 2]) << 16
        | static_cast<std::uint32_t>(bytes[offset + 3]) << 24;
}

}

std::vector<ArchiveEntry> listZipEntries(const std::vector<unsigned char>& bytes) {
    constexpr std::size_t maximumEntries = 100000;
    std::vector<ArchiveEntry> entries;
    if (bytes.size() < 22)
        return entries;
    const std::size_t searchStart = bytes.size() > 65557 ? bytes.size() - 65557 : 0;
    std::size_t endRecord = bytes.size() - 22;
    while (true) {
        if (read32(bytes, endRecord) == 0x06054b50)
            break;
        if (endRecord == searchStart)
            return entries;
        --endRecord;
    }

    const auto entryCount = read16(bytes, endRecord + 10);
    const auto directorySize = read32(bytes, endRecord + 12);
    const auto directoryOffset = read32(bytes, endRecord + 16);
    if (entryCount == 0xffff || directorySize == 0xffffffff || directoryOffset == 0xffffffff
            || directoryOffset > bytes.size() || directorySize > bytes.size() - directoryOffset)
        return entries;

    std::size_t cursor = directoryOffset;
    const auto directoryEnd = directoryOffset + directorySize;
    while (cursor + 46 <= directoryEnd && entries.size() < std::min<std::size_t>(entryCount, maximumEntries)) {
        if (read32(bytes, cursor) != 0x02014b50)
            break;
        const auto method = read16(bytes, cursor + 10);
        const auto crc = read32(bytes, cursor + 16);
        const auto compressedSize = read32(bytes, cursor + 20);
        const auto size = read32(bytes, cursor + 24);
        const auto nameLength = read16(bytes, cursor + 28);
        const auto extraLength = read16(bytes, cursor + 30);
        const auto commentLength = read16(bytes, cursor + 32);
        const std::size_t recordLength = 46ULL + nameLength + extraLength + commentLength;
        if (recordLength > directoryEnd - cursor)
            break;
        std::string name(reinterpret_cast<const char*>(bytes.data() + cursor + 46), nameLength);
        const bool isDirectory = !name.empty() && (name.back() == '/' || name.back() == '\\');
        entries.push_back({name, size, compressedSize, crc, method, isDirectory});
        cursor += recordLength;
    }
    return entries;
}

std::string compressionName(std::uint16_t method) {
    switch (method) {
    case 0: return "Stored";
    case 8: return "Deflate";
    case 12: return "BZip2";
    case 14: return "LZMA";
    case 93: return "Zstandard";
    default: return "Method " + std::to_string(method);
    }
}

std::string lowercaseAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::string detectFileType(const std::vector<unsigned char>& bytes, const std::filesystem::path& path) {
    if (bytes.size() >= 4 && bytes[0] == 0xca && bytes[1] == 0xfe && bytes[2] == 0xba && bytes[3] == 0xbe)
        return "Java class";
    const bool isZip = bytes.size() >= 4 && bytes[0] == 'P' && bytes[1] == 'K'
        && ((bytes[2] == 3 && bytes[3] == 4) || (bytes[2] == 5 && bytes[3] == 6) || (bytes[2] == 7 && bytes[3] == 8));
    if (isZip) {
        const auto extension = lowercaseAscii(path.extension().string());
        if (extension == ".war") return "Java Web Archive (WAR)";
        if (extension == ".ear") return "Java Enterprise Archive (EAR)";
        if (extension == ".jar") return "Java archive (JAR)";
        return "ZIP archive";
    }
    if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z')
        return "Windows PE executable";
    return path.extension().string().empty() ? "Unknown binary" : path.extension().string() + " file";
}

}