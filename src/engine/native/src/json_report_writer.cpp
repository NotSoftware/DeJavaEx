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

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace dejavaex {

namespace {

std::string escapeJson(const std::string& value) {
    std::ostringstream output;
    for (unsigned char character : value) {
        switch (character) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (character < 0x20)
                output << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(character) << std::dec;
            else
                output << character;
        }
    }
    return output.str();
}

void writeStringArray(const std::vector<std::string>& values) {
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index) std::cout << ',';
        std::cout << '"' << escapeJson(values[index]) << '"';
    }
}

}

void writeJsonReport(const AnalysisReport& report) {
    std::cout << "{\"fileName\":\"" << escapeJson(report.fileName)
              << "\",\"filePath\":\"" << escapeJson(report.filePath)
              << "\",\"fileType\":\"" << escapeJson(report.fileType)
              << "\",\"sizeBytes\":" << report.sizeBytes
              << ",\"md5\":\"" << report.md5
              << "\",\"sha1\":\"" << report.sha1
              << "\",\"sha256\":\"" << report.sha256
              << "\",\"entropy\":" << std::fixed << std::setprecision(4) << report.entropy
              << ",\"packer\":{\"verdict\":\"" << escapeJson(report.packer.verdict)
              << "\",\"confidence\":\"" << escapeJson(report.packer.confidence)
              << "\",\"level\":\"" << report.packer.level << "\",\"evidence\":[";
    writeStringArray(report.packer.evidence);
    std::cout << "]},\"classes\":[";
    writeStringArray(report.classes);
    std::cout << "],\"entries\":[";
    for (std::size_t index = 0; index < report.entries.size(); ++index) {
        if (index) std::cout << ',';
        const auto& entry = report.entries[index];
        std::cout << "{\"path\":\"" << escapeJson(entry.path)
                  << "\",\"size\":" << entry.size
                  << ",\"compressedSize\":" << entry.compressedSize
                  << ",\"crc32\":\"" << std::hex << std::setw(8) << std::setfill('0') << entry.crc << std::dec
                  << "\",\"compression\":\"" << compressionName(entry.method)
                  << "\",\"isDirectory\":" << (entry.isDirectory ? "true" : "false") << '}';
    }
    std::cout << "],\"regions\":[";
    for (std::size_t index = 0; index < report.regions.size(); ++index) {
        if (index) std::cout << ',';
        const auto& region = report.regions[index];
        std::cout << "{\"index\":" << region.index << ",\"offset\":" << region.offset
                  << ",\"size\":" << region.size << ",\"entropy\":" << region.entropy << '}';
    }
    std::cout << "],\"strings\":[";
    writeStringArray(report.strings);
    std::cout << "],\"peAnalysis\":";
    if (!report.peAnalysis) {
        std::cout << "null";
    } else {
        const auto& pe = *report.peAnalysis;
        std::cout << "{\"architecture\":\"" << escapeJson(pe.architecture)
                  << "\",\"subsystem\":\"" << escapeJson(pe.subsystem)
                  << "\",\"timestamp\":" << pe.timestamp
                  << ",\"entryPointRva\":" << pe.entryPointRva
                  << ",\"imageBase\":" << pe.imageBase
                  << ",\"sectionCount\":" << pe.sectionCount
                  << ",\"is64Bit\":" << (pe.is64Bit ? "true" : "false")
                  << ",\"isDll\":" << (pe.isDll ? "true" : "false")
                  << ",\"hasOverlay\":" << (pe.hasOverlay ? "true" : "false")
                  << ",\"overlayBytes\":" << pe.overlayBytes << ",\"sections\":[";
        for (std::size_t index = 0; index < pe.sections.size(); ++index) {
            if (index) std::cout << ',';
            const auto& section = pe.sections[index];
            std::cout << "{\"name\":\"" << escapeJson(section.name)
                      << "\",\"virtualAddress\":" << section.virtualAddress
                      << ",\"virtualSize\":" << section.virtualSize
                      << ",\"rawOffset\":" << section.rawOffset
                      << ",\"rawSize\":" << section.rawSize
                      << ",\"characteristics\":" << section.characteristics
                      << ",\"entropy\":" << section.entropy
                      << ",\"executable\":" << (section.executable ? "true" : "false")
                      << ",\"writable\":" << (section.writable ? "true" : "false") << '}';
        }
        std::cout << "],\"imports\":[";
        for (std::size_t index = 0; index < pe.imports.size(); ++index) {
            if (index) std::cout << ',';
            const auto& imported = pe.imports[index];
            std::cout << "{\"module\":\"" << escapeJson(imported.module)
                      << "\",\"symbol\":\"" << escapeJson(imported.symbol)
                      << "\",\"byOrdinal\":" << (imported.byOrdinal ? "true" : "false")
                      << ",\"ordinal\":" << imported.ordinal << '}';
        }
        std::cout << "]}";
    }
    std::cout << "}\n";
}

}