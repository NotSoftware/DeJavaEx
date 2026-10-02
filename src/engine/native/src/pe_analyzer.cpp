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
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace dejavaex {
namespace {

bool hasRange(const std::vector<unsigned char>& bytes, std::size_t offset, std::size_t length) {
    return offset <= bytes.size() && length <= bytes.size() - offset;
}

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

std::uint64_t read64(const std::vector<unsigned char>& bytes, std::size_t offset) {
    return static_cast<std::uint64_t>(read32(bytes, offset))
        | static_cast<std::uint64_t>(read32(bytes, offset + 4)) << 32;
}

std::string readCString(const std::vector<unsigned char>& bytes, std::size_t offset, std::size_t limit) {
    if (offset >= bytes.size())
        return {};
    const auto end = std::min(bytes.size(), offset + std::min<std::size_t>(limit, bytes.size() - offset));
    std::size_t cursor = offset;
    while (cursor < end && bytes[cursor] != 0)
        ++cursor;
    return std::string(reinterpret_cast<const char*>(bytes.data() + offset), cursor - offset);
}

std::string sectionName(const std::vector<unsigned char>& bytes, std::size_t offset) {
    std::string name;
    for (std::size_t index = 0; index < 8 && bytes[offset + index] != 0; ++index)
        name.push_back(static_cast<char>(bytes[offset + index]));
    return name;
}

std::string machineName(std::uint16_t machine) {
    switch (machine) {
    case 0x014c: return "x86";
    case 0x8664: return "x64";
    case 0x01c0: case 0x01c4: return "ARM";
    case 0xaa64: return "ARM64";
    default: {
        std::ostringstream output;
        output << "Unknown (0x" << std::hex << machine << ')';
        return output.str();
    }
    }
}

std::string subsystemName(std::uint16_t subsystem) {
    switch (subsystem) {
    case 1: return "Native";
    case 2: return "Windows GUI";
    case 3: return "Windows console";
    case 7: return "POSIX console";
    case 9: return "Windows CE GUI";
    case 10: return "EFI application";
    case 14: return "Xbox";
    case 16: return "Windows boot application";
    default: return "Subsystem " + std::to_string(subsystem);
    }
}

}

std::optional<PeAnalysis> analyzePeImage(const std::vector<unsigned char>& bytes) {
    if (bytes.size() < 64 || bytes[0] != 'M' || bytes[1] != 'Z')
        return std::nullopt;
    const auto peOffset = static_cast<std::size_t>(read32(bytes, 0x3c));
    if (!hasRange(bytes, peOffset, 24) || bytes[peOffset] != 'P' || bytes[peOffset + 1] != 'E'
            || bytes[peOffset + 2] != 0 || bytes[peOffset + 3] != 0)
        return std::nullopt;

    const auto coffOffset = peOffset + 4;
    const auto machine = read16(bytes, coffOffset);
    const auto numberOfSections = read16(bytes, coffOffset + 2);
    const auto timestamp = read32(bytes, coffOffset + 4);
    const auto optionalHeaderSize = read16(bytes, coffOffset + 16);
    const auto characteristics = read16(bytes, coffOffset + 18);
    const auto optionalOffset = coffOffset + 20;
    if (numberOfSections == 0 || numberOfSections > 96 || optionalHeaderSize < 70
            || !hasRange(bytes, optionalOffset, optionalHeaderSize))
        return std::nullopt;

    const auto magic = read16(bytes, optionalOffset);
    const bool is64Bit = magic == 0x20b;
    if (magic != 0x10b && !is64Bit)
        return std::nullopt;
    const auto directoryOffset = optionalOffset + (is64Bit ? 112 : 96);
    const auto directoryCountOffset = optionalOffset + (is64Bit ? 108 : 92);
    const auto entryPoint = read32(bytes, optionalOffset + 16);
    const auto imageBase = is64Bit ? read64(bytes, optionalOffset + 24) : read32(bytes, optionalOffset + 28);
    const auto subsystem = read16(bytes, optionalOffset + 68);
    const auto sizeOfHeaders = read32(bytes, optionalOffset + 60);
    const auto directoryCount = optionalHeaderSize >= (is64Bit ? 112 : 96)
        ? read32(bytes, directoryCountOffset) : 0;

    PeAnalysis result;
    result.architecture = machineName(machine);
    result.timestamp = timestamp;
    result.entryPointRva = entryPoint;
    result.imageBase = imageBase;
    result.subsystem = subsystemName(subsystem);
    result.is64Bit = is64Bit;
    result.isDll = (characteristics & 0x2000) != 0;

    const auto sectionTable = optionalOffset + optionalHeaderSize;
    if (!hasRange(bytes, sectionTable, static_cast<std::size_t>(numberOfSections) * 40))
        return std::nullopt;
    std::uint64_t rawEnd = std::min<std::uint64_t>(sizeOfHeaders, bytes.size());
    result.sections.reserve(numberOfSections);
    for (std::uint16_t index = 0; index < numberOfSections; ++index) {
        const auto offset = sectionTable + static_cast<std::size_t>(index) * 40;
        PeSection section;
        section.name = sectionName(bytes, offset);
        section.virtualSize = read32(bytes, offset + 8);
        section.virtualAddress = read32(bytes, offset + 12);
        section.rawSize = read32(bytes, offset + 16);
        section.rawOffset = read32(bytes, offset + 20);
        section.characteristics = read32(bytes, offset + 36);
        section.executable = (section.characteristics & 0x20000000) != 0;
        section.writable = (section.characteristics & 0x80000000) != 0;
        if (section.rawSize > 0 && hasRange(bytes, section.rawOffset, section.rawSize)) {
            section.entropy = calculateEntropy(bytes, section.rawOffset, section.rawOffset + section.rawSize);
            rawEnd = std::max<std::uint64_t>(rawEnd, static_cast<std::uint64_t>(section.rawOffset) + section.rawSize);
        }
        result.sections.push_back(std::move(section));
    }
    result.sectionCount = static_cast<std::uint16_t>(result.sections.size());
    result.hasOverlay = rawEnd < bytes.size();
    result.overlayBytes = result.hasOverlay ? bytes.size() - rawEnd : 0;

    if (directoryCount > 1 && optionalHeaderSize >= (is64Bit ? 120 : 104)) {
        const auto importRva = read32(bytes, directoryOffset + 8);
        const auto importSize = read32(bytes, directoryOffset + 12);
        const auto rvaToOffset = [&](std::uint32_t rva) -> std::size_t {
            if (rva < sizeOfHeaders && rva < bytes.size())
                return rva;
            for (const auto& section : result.sections) {
                const auto span = std::max(section.virtualSize, section.rawSize);
                if (rva < section.virtualAddress || rva - section.virtualAddress >= span)
                    continue;
                const auto delta = rva - section.virtualAddress;
                if (delta >= section.rawSize)
                    return bytes.size();
                const auto offset = static_cast<std::uint64_t>(section.rawOffset) + delta;
                return offset < bytes.size() ? static_cast<std::size_t>(offset) : bytes.size();
            }
            return bytes.size();
        };

        auto descriptorOffset = importRva == 0 || importSize == 0 ? bytes.size() : rvaToOffset(importRva);
        const auto descriptorLimit = std::min<std::uint32_t>(importSize, 1024u * 1024u);
        std::size_t walked = 0;
        while (descriptorOffset < bytes.size() && hasRange(bytes, descriptorOffset, 20)
            && walked + 20 <= descriptorLimit && result.imports.size() < 10000) {
            const auto originalThunk = read32(bytes, descriptorOffset);
            const auto nameRva = read32(bytes, descriptorOffset + 12);
            const auto firstThunk = read32(bytes, descriptorOffset + 16);
            if (originalThunk == 0 && nameRva == 0 && firstThunk == 0)
                break;
            const auto moduleOffset = rvaToOffset(nameRva);
            const auto module = readCString(bytes, moduleOffset, 512);
            const auto thunkRva = originalThunk != 0 ? originalThunk : firstThunk;
            auto thunkOffset = rvaToOffset(thunkRva);
            const std::size_t thunkSize = is64Bit ? 8 : 4;
            const std::uint64_t ordinalFlag = is64Bit ? 0x8000000000000000ULL : 0x80000000ULL;
            for (std::size_t thunkIndex = 0; thunkOffset < bytes.size() && result.imports.size() < 10000
                    && thunkIndex < 4096; ++thunkIndex, thunkOffset += thunkSize) {
                if (!hasRange(bytes, thunkOffset, thunkSize))
                    break;
                const auto thunk = is64Bit ? read64(bytes, thunkOffset) : read32(bytes, thunkOffset);
                if (thunk == 0)
                    break;
                if ((thunk & ordinalFlag) != 0) {
                    const auto ordinal = static_cast<std::uint16_t>(thunk & 0xffff);
                    result.imports.push_back({module, "#" + std::to_string(ordinal), true, ordinal});
                    continue;
                }
                if (thunk > std::numeric_limits<std::uint32_t>::max())
                    continue;
                const auto importNameOffset = rvaToOffset(static_cast<std::uint32_t>(thunk));
                if (!hasRange(bytes, importNameOffset, 3))
                    continue;
                auto symbol = readCString(bytes, importNameOffset + 2, 512);
                if (!symbol.empty())
                    result.imports.push_back({module, std::move(symbol), false, 0});
            }
            descriptorOffset += 20;
            walked += 20;
        }
    }
    return result;
}

}
