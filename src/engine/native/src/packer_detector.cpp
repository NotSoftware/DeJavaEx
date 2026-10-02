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
#include <string>
#include <vector>

namespace dejavaex {

std::vector<std::string> detectPackerSignals(const std::vector<std::string>& strings) {
    const std::vector<std::string> signatures = {
        "allatori", "zelix", "zkm", "stringer", "dasho", "skidfuscator",
        "jshield", "jpack", "proguard", "yguard", "pack200", "packed by"
    };
    std::vector<std::string> evidence;
    for (const auto& value : strings) {
        const auto lowered = lowercaseAscii(value);
        for (const auto& signature : signatures) {
            if (lowered.find(signature) == std::string::npos)
                continue;
            const auto item = "Tooling marker: " + signature;
            if (std::find(evidence.begin(), evidence.end(), item) == evidence.end())
                evidence.push_back(item);
        }
    }
    return evidence;
}

PackerAssessment assessPacker(const std::string& fileType, double fileEntropy, const std::vector<std::string>& strings) {
    PackerAssessment assessment{"No clear packer evidence", "Low confidence · no signature matched", "low", detectPackerSignals(strings)};
    const bool isJava = fileType.find("Java") != std::string::npos;
    if (!assessment.evidence.empty()) {
        assessment.verdict = "Known tooling marker";
        assessment.confidence = "High confidence · named tooling marker";
        assessment.level = "high";
    } else if (isJava && fileEntropy >= 7.55 && strings.size() < 24) {
        assessment.verdict = "Possible packing or encryption";
        assessment.confidence = "Heuristic · high entropy and few readable strings";
        assessment.level = "medium";
        assessment.evidence.push_back("High overall entropy with a low readable-string count; compression can produce similar results.");
    } else {
        assessment.evidence.push_back("No known Java packer or protector marker was found. This does not rule out packing.");
    }
    return assessment;
}

}