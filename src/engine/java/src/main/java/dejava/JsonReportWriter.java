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

package dejava;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class JsonReportWriter {
    private JsonReportWriter() {}

    static void write(List<String> classes, List<StaticAnalyzer.Call> calls,
            List<StaticAnalyzer.ClassSummary> classAnalysis,
            Map<String, LinkedHashSet<String>> indicators, Set<String> packerSignals,
            Set<String> strings, List<StringDecoder.DecodedString> decodedStrings) {
        StringBuilder output = new StringBuilder("{\"classes\":[");
        for (int index = 0; index < classes.size(); index++) {
            if (index > 0) output.append(',');
            output.append(quote(classes.get(index)));
        }
        output.append("],\"classAnalysis\":[");
        for (int index = 0; index < classAnalysis.size(); index++) {
            if (index > 0) output.append(',');
            StaticAnalyzer.ClassSummary summary = classAnalysis.get(index);
            output.append("{\"name\":").append(quote(summary.name))
                .append(",\"majorVersion\":").append(summary.majorVersion)
                .append(",\"minorVersion\":").append(summary.minorVersion)
                .append(",\"methodCount\":").append(summary.methodCount)
                .append(",\"fieldCount\":").append(summary.fieldCount)
                .append(",\"constantTextCount\":").append(summary.constantTextCount)
                .append(",\"callCount\":").append(summary.callCount)
                .append(",\"dynamicCallCount\":").append(summary.dynamicCallCount).append('}');
        }
        output.append("],\"calls\":[");
        for (int index = 0; index < calls.size(); index++) {
            if (index > 0) output.append(',');
            StaticAnalyzer.Call call = calls.get(index);
            output.append("{\"class\":").append(quote(call.className))
                .append(",\"method\":").append(quote(call.methodName))
                .append(",\"descriptor\":").append(quote(call.methodDescriptor))
                .append(",\"opcode\":").append(quote(call.opcode))
                .append(",\"owner\":").append(quote(call.owner))
                .append(",\"target\":").append(quote(call.targetName))
                .append(",\"target_descriptor\":").append(quote(call.targetDescriptor)).append('}');
        }
        output.append("],\"indicators\":[");
        boolean firstIndicator = true;
        for (Map.Entry<String, LinkedHashSet<String>> indicator : indicators.entrySet()) {
            for (String evidence : indicator.getValue()) {
                if (!firstIndicator) output.append(',');
                firstIndicator = false;
                output.append("{\"category\":").append(quote(indicator.getKey()))
                    .append(",\"evidence\":").append(quote(evidence)).append('}');
            }
        }
        output.append("],\"packerSignals\":[");
        appendStrings(output, packerSignals);
        output.append("],\"strings\":[");
        appendStrings(output, strings);
        output.append("],\"decodedStrings\":[");
        appendDecodedStrings(output, decodedStrings);
        System.out.println(output.append("]}").toString());
    }

    static void writeDecodedStrings(List<StringDecoder.DecodedString> decodedStrings) {
        StringBuilder output = new StringBuilder("[");
        appendDecodedStrings(output, decodedStrings);
        System.out.println(output.append(']').toString());
    }

    private static void appendDecodedStrings(StringBuilder output, List<StringDecoder.DecodedString> values) {
        for (int index = 0; index < values.size(); index++) {
            if (index > 0) output.append(',');
            StringDecoder.DecodedString value = values.get(index);
            output.append("{\"original\":").append(quote(value.original))
                .append(",\"encoding\":").append(quote(value.encoding))
                .append(",\"decoded\":").append(quote(value.decoded))
                .append(",\"source\":").append(quote(value.source)).append('}');
        }
    }

    private static void appendStrings(StringBuilder output, Iterable<String> values) {
        boolean first = true;
        for (String value : values) {
            if (!first) output.append(',');
            first = false;
            output.append(quote(value));
        }
    }

    private static String quote(String value) {
        StringBuilder result = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"': result.append("\\\""); break;
                case '\\': result.append("\\\\"); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (Character.isHighSurrogate(character)) {
                        if (index + 1 < value.length() && Character.isLowSurrogate(value.charAt(index + 1))) {
                            appendUnicodeEscape(result, character);
                            appendUnicodeEscape(result, value.charAt(++index));
                        } else {
                            appendLiteralUnicodeEscape(result, character);
                        }
                    } else if (Character.isLowSurrogate(character)) {
                        appendLiteralUnicodeEscape(result, character);
                    } else if (character < 0x20 || character > 0x7e) {
                        appendUnicodeEscape(result, character);
                    } else {
                        result.append(character);
                    }
            }
        }
        return result.append('"').toString();
    }

    private static void appendUnicodeEscape(StringBuilder output, char character) {
        output.append("\\u");
        appendHexCodeUnit(output, character);
    }

    private static void appendLiteralUnicodeEscape(StringBuilder output, char character) {
        output.append("\\\\u");
        appendHexCodeUnit(output, character);
    }

    private static void appendHexCodeUnit(StringBuilder output, char character) {
        for (int shift = 12; shift >= 0; shift -= 4)
            output.append("0123456789abcdef".charAt((character >> shift) & 0xf));
    }
}