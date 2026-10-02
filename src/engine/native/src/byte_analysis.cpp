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
#include <cmath>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace dejavaex {

namespace {
constexpr std::size_t kMaximumStrings = 5000;
}

double calculateEntropy(const std::vector<unsigned char>& bytes, std::size_t start, std::size_t end) {
    if (end <= start)
        return 0.0;
    std::uint64_t frequencies[256]{};
    for (std::size_t index = start; index < end; ++index)
        ++frequencies[bytes[index]];
    const auto length = static_cast<double>(end - start);
    double result = 0.0;
    for (const auto count : frequencies) {
        if (count == 0)
            continue;
        const double probability = static_cast<double>(count) / length;
        result -= probability * std::log2(probability);
    }
    return result;
}

std::vector<std::string> extractStrings(const std::vector<unsigned char>& bytes) {
    std::set<std::string> found;
    std::string current;
    for (const auto byte : bytes) {
        if (byte >= 0x20 && byte <= 0x7e) {
            current.push_back(static_cast<char>(byte));
        } else {
            if (current.size() >= 5 && found.size() < kMaximumStrings)
                found.insert(current);
            current.clear();
        }
    }
    if (current.size() >= 5 && found.size() < kMaximumStrings)
        found.insert(current);

    for (std::size_t index = 0; index + 9 < bytes.size() && found.size() < kMaximumStrings; ++index) {
        std::string wide;
        std::size_t cursor = index;
        while (cursor + 1 < bytes.size() && bytes[cursor] >= 0x20 && bytes[cursor] <= 0x7e && bytes[cursor + 1] == 0) {
            wide.push_back(static_cast<char>(bytes[cursor]));
            cursor += 2;
        }
        if (wide.size() >= 5) {
            found.insert(wide);
            index = cursor - 1;
        }
    }
    return {found.begin(), found.end()};
}

std::vector<Region> createEntropyRegions(const std::vector<unsigned char>& bytes) {
    std::vector<Region> regions;
    if (bytes.empty())
        return regions;
    const auto count = std::min<std::size_t>(48, bytes.size());
    regions.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto start = bytes.size() * index / count;
        const auto end = bytes.size() * (index + 1) / count;
        regions.push_back({index, start, end - start, calculateEntropy(bytes, start, end)});
    }
    return regions;
}

}
