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

#define NOMINMAX
#include "dejavaex/analysis.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace dejavaex {

namespace {
constexpr std::uint64_t kMaxInputBytes = 1024ULL * 1024ULL * 1024ULL;
}

std::vector<unsigned char> readFile(const std::filesystem::path& path) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size > kMaxInputBytes)
        throw std::runtime_error("Input file is unavailable or larger than the 1 GiB analysis limit.");
    std::ifstream input(path, std::ios::binary);
    if (!input)
        throw std::runtime_error("Unable to open input file.");
    std::vector<unsigned char> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!input)
            throw std::runtime_error("Could not read the complete input file.");
    }
    return bytes;
}

std::string calculateHash(const std::vector<unsigned char>& bytes, LPCWSTR algorithmName) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLength = 0;
    DWORD hashLength = 0;
    DWORD returned = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, algorithmName, nullptr, 0) < 0)
        throw std::runtime_error("Windows could not initialize a requested file hash.");
    auto closeAlgorithm = [&]() { if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); };
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &returned, 0) < 0
        || BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &returned, 0) < 0) {
        closeAlgorithm();
        throw std::runtime_error("Could not query the Windows hash provider.");
    }
    std::vector<UCHAR> object(objectLength);
    std::vector<UCHAR> digest(hashLength);
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0) < 0) {
        closeAlgorithm();
        throw std::runtime_error("Could not create the SHA-256 hash context.");
    }
    const auto chunkLimit = static_cast<std::size_t>(std::numeric_limits<ULONG>::max());
    for (std::size_t offset = 0; offset < bytes.size(); offset += chunkLimit) {
        const auto count = static_cast<ULONG>(std::min(chunkLimit, bytes.size() - offset));
        if (BCryptHashData(hash, const_cast<PUCHAR>(bytes.data() + offset), count, 0) < 0) {
            BCryptDestroyHash(hash);
            closeAlgorithm();
            throw std::runtime_error("Windows hash processing failed.");
        }
    }
    const auto status = BCryptFinishHash(hash, digest.data(), hashLength, 0);
    BCryptDestroyHash(hash);
    closeAlgorithm();
    if (status < 0)
        throw std::runtime_error("Windows could not finalize a file hash.");
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (UCHAR byte : digest)
        output << std::setw(2) << static_cast<unsigned int>(byte);
    return output.str();
}

std::string calculateMd5(const std::vector<unsigned char>& bytes) {
    return calculateHash(bytes, BCRYPT_MD5_ALGORITHM);
}

std::string calculateSha1(const std::vector<unsigned char>& bytes) {
    return calculateHash(bytes, BCRYPT_SHA1_ALGORITHM);
}

std::string calculateSha256(const std::vector<unsigned char>& bytes) {
    return calculateHash(bytes, BCRYPT_SHA256_ALGORITHM);
}

}