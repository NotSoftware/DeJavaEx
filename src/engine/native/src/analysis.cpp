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
#include "dejavaex/engine.hpp"

#include <algorithm>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

namespace dejavaex {

int analyzeFile(const std::filesystem::path& path) {
    try {
        const auto bytes = readFile(path);
        AnalysisReport report;
        const auto fileName = path.filename().u8string();
        const auto filePath = path.u8string();
        report.fileName.assign(fileName.begin(), fileName.end());
        report.filePath.assign(filePath.begin(), filePath.end());
        report.fileType = detectFileType(bytes, path);
        report.sizeBytes = bytes.size();
        report.peAnalysis = analyzePeImage(bytes);
        report.md5 = calculateMd5(bytes);
        report.sha1 = calculateSha1(bytes);
        report.sha256 = calculateSha256(bytes);
        report.entropy = calculateEntropy(bytes, 0, bytes.size());
        report.strings = extractStrings(bytes);
        report.entries = listZipEntries(bytes);
        report.regions = createEntropyRegions(bytes);

        if (report.fileType == "Java class")
            report.classes.push_back(report.fileName);
        for (const auto& entry : report.entries) {
            const auto lowered = lowercaseAscii(entry.path);
            if (lowered.size() >= 6 && lowered.compare(lowered.size() - 6, 6, ".class") == 0)
                report.classes.push_back(entry.path);
        }

        report.packer = assessPacker(report.fileType, report.entropy, report.strings);
        writeJsonReport(report);
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Static analysis failed: " << exception.what() << '\n';
        return 1;
    }
}

}
