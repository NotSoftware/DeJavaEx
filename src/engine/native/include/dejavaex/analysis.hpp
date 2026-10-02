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

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace dejavaex {

struct ArchiveEntry {
    std::string path;
    std::uint32_t size;
    std::uint32_t compressedSize;
    std::uint32_t crc;
    std::uint16_t method;
    bool isDirectory;
};

struct Region {
    std::size_t index;
    std::uint64_t offset;
    std::uint64_t size;
    double entropy;
};

struct PackerAssessment {
    std::string verdict;
    std::string confidence;
    std::string level;
    std::vector<std::string> evidence;
};

struct AnalysisReport {
    std::string fileName;
    std::string filePath;
    std::string fileType;
    std::uint64_t sizeBytes = 0;
    std::string sha256;
    double entropy = 0.0;
    PackerAssessment packer;
    std::vector<std::string> classes;
    std::vector<ArchiveEntry> entries;
    std::vector<Region> regions;
    std::vector<std::string> strings;
};

std::vector<unsigned char> readFile(const std::filesystem::path& path);
std::string calculateSha256(const std::vector<unsigned char>& bytes);
double calculateEntropy(const std::vector<unsigned char>& bytes, std::size_t start, std::size_t end);
std::vector<std::string> extractStrings(const std::vector<unsigned char>& bytes);
std::vector<Region> createEntropyRegions(const std::vector<unsigned char>& bytes);
std::vector<ArchiveEntry> listZipEntries(const std::vector<unsigned char>& bytes);
std::string compressionName(std::uint16_t method);
std::string lowercaseAscii(std::string value);
std::string detectFileType(const std::vector<unsigned char>& bytes, const std::filesystem::path& path);
std::vector<std::string> detectPackerSignals(const std::vector<std::string>& strings);
PackerAssessment assessPacker(const std::string& fileType, double fileEntropy, const std::vector<std::string>& strings);
void writeJsonReport(const AnalysisReport& report);

}