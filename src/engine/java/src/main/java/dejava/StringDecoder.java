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

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class StringDecoder {
    private static final int MAX_INPUT_BYTES = 1024 * 1024;
    private static final int MAX_INPUT_STRINGS = 10000;
    private static final int MAX_TOTAL_BYTES = 64 * 1024 * 1024;
    private static final int MAX_RESULTS_PER_STRING = 8;

    private StringDecoder() {}

    static final class DecodedString {
        final String original;
        final String encoding;
        final String decoded;
        final String source;

        DecodedString(String original, String encoding, String decoded, String source) {
            this.original = original;
            this.encoding = encoding;
            this.decoded = decoded;
            this.source = source;
        }
    }

    private static final class Candidate {
        final String encoding;
        final String value;

        Candidate(String encoding, String value) {
            this.encoding = encoding;
            this.value = value;
        }
    }

    private static final class Pending {
        final String value;
        final String chain;
        final int depth;

        Pending(String value, String chain, int depth) {
            this.value = value;
            this.chain = chain;
            this.depth = depth;
        }
    }

    static List<DecodedString> decode(Iterable<String> strings, String source) {
        List<DecodedString> results = new ArrayList<>();
        for (String original : strings) {
            if (original == null || original.getBytes(StandardCharsets.UTF_8).length > MAX_INPUT_BYTES)
                continue;
            List<Pending> pending = new ArrayList<>();
            pending.add(new Pending(original, "", 0));
            Set<String> seen = new HashSet<>();
            while (!pending.isEmpty() && seen.size() < MAX_RESULTS_PER_STRING) {
                List<Pending> next = new ArrayList<>();
                for (Pending item : pending) {
                    for (Candidate candidate : decodeOnePass(item.value)) {
                        String chain = item.chain.isEmpty() ? candidate.encoding : item.chain + " -> " + candidate.encoding;
                        String key = chain + "\u0000" + candidate.value;
                        if (!seen.add(key))
                            continue;
                        results.add(new DecodedString(original, chain, candidate.value, source));
                        if (item.depth < 2)
                            next.add(new Pending(candidate.value, chain, item.depth + 1));
                        if (seen.size() >= MAX_RESULTS_PER_STRING)
                            break;
                    }
                    if (seen.size() >= MAX_RESULTS_PER_STRING)
                        break;
                }
                pending = next;
            }
        }
        return results;
    }

    static List<DecodedString> decodeRequestFile(Path path) throws IOException {
        List<String> strings = new ArrayList<>();
        long totalBytes = 0;
        try (InputStream input = Files.newInputStream(path)) {
            int count = readLittleEndianInt(input);
            if (count < 0 || count > MAX_INPUT_STRINGS)
                throw new IOException("Invalid string-decoder request.");
            for (int index = 0; index < count; index++) {
                int length = readLittleEndianInt(input);
                if (length < 0 || length > MAX_INPUT_BYTES || totalBytes + length > MAX_TOTAL_BYTES)
                    throw new IOException("String-decoder request exceeds its size limit.");
                byte[] bytes = input.readNBytes(length);
                if (bytes.length != length)
                    throw new IOException("String-decoder request is truncated.");
                strings.add(new String(bytes, StandardCharsets.UTF_8));
                totalBytes += length;
            }
            if (input.read() != -1)
                throw new IOException("String-decoder request has trailing data.");
        }
        return decode(strings, "C++ byte scan");
    }

    private static int readLittleEndianInt(InputStream input) throws IOException {
        int first = input.read();
        int second = input.read();
        int third = input.read();
        int fourth = input.read();
        if ((first | second | third | fourth) < 0)
            throw new IOException("String-decoder request is truncated.");
        return first | second << 8 | third << 16 | fourth << 24;
    }

    private static List<Candidate> decodeOnePass(String input) {
        List<Candidate> results = new ArrayList<>();
        List<String> literals = decodeJavaStringLiterals(input);
        for (String literal : literals)
            add(results, input, "Java UTF-16 Unicode escapes", literal);
        if (literals.isEmpty()) {
            String unescaped = decodeJavaEscapes(input);
            if (unescaped != null)
                add(results, input, "UTF Unicode escapes", unescaped);
        }

        if (input.indexOf('%') >= 0) {
            try {
                String value = URLDecoder.decode(input, StandardCharsets.UTF_8);
                if (!value.equals(input))
                    add(results, input, "URL percent encoding", value);
            } catch (IllegalArgumentException ignored) {
            }
        }

        decodeBase64Runs(input, results);
        decodeHexRuns(input, results);
        return results;
    }

    private static void decodeBase64Runs(String input, List<Candidate> results) {
        for (int start = 0; start < input.length();) {
            while (start < input.length() && !isBase64Character(input.charAt(start))) start++;
            int end = start;
            while (end < input.length() && isBase64Character(input.charAt(end))) end++;
            if (end - start >= 8) {
                String encoded = input.substring(start, end);
                try {
                    byte[] bytes = encoded.indexOf('-') >= 0 || encoded.indexOf('_') >= 0
                        ? Base64.getUrlDecoder().decode(encoded)
                        : Base64.getDecoder().decode(encoded);
                    String decoded = decodeUtf8(bytes);
                    if (decoded != null)
                        add(results, input, "Base64", decoded);
                } catch (IllegalArgumentException ignored) {
                }
            }
            start = end > start ? end : start + 1;
        }
    }

    private static void decodeHexRuns(String input, List<Candidate> results) {
        for (int start = 0; start < input.length();) {
            while (start < input.length() && hexValue(input.charAt(start)) < 0) start++;
            int end = start;
            while (end < input.length() && hexValue(input.charAt(end)) >= 0) end++;
            int length = end - start;
            if (length >= 8 && length % 2 == 0) {
                byte[] bytes = new byte[length / 2];
                for (int index = 0; index < bytes.length; index++)
                    bytes[index] = (byte) ((hexValue(input.charAt(start + index * 2)) << 4)
                        | hexValue(input.charAt(start + index * 2 + 1)));
                String decoded = decodeUtf8(bytes);
                if (decoded != null)
                    add(results, input, "Hex", decoded);
            }
            start = end > start ? end : start + 1;
        }
    }

    private static String decodeUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException ignored) {
            return null;
        }
    }

    private static void add(List<Candidate> results, String input, String encoding, String value) {
        if (!value.equals(input) && isReadableText(value))
            results.add(new Candidate(encoding, value));
    }

    private static boolean isReadableText(String value) {
        int codePoints = 0;
        int meaningful = 0;
        for (int index = 0; index < value.length();) {
            int codePoint = value.codePointAt(index);
            index += Character.charCount(codePoint);
            codePoints++;
            if (Character.isISOControl(codePoint) && codePoint != '\n' && codePoint != '\r' && codePoint != '\t')
                return false;
            if (Character.isLetterOrDigit(codePoint))
                meaningful++;
        }
        return codePoints >= 4 && meaningful >= 2;
    }

    private static List<String> decodeJavaStringLiterals(String input) {
        List<String> values = new ArrayList<>();
        for (int index = 0; index < input.length(); index++) {
            if (input.charAt(index) != '"')
                continue;
            int start = index + 1;
            int cursor = start;
            boolean hasEscape = false;
            while (cursor < input.length()) {
                char current = input.charAt(cursor);
                if (current == '\\') {
                    hasEscape = true;
                    cursor = Math.min(input.length(), cursor + 2);
                    if (cursor > 0 && input.charAt(cursor - 1) == 'u') {
                        while (cursor < input.length() && input.charAt(cursor) == 'u') cursor++;
                        cursor = Math.min(input.length(), cursor + 4);
                    }
                    continue;
                }
                if (current == '"')
                    break;
                cursor++;
            }
            if (cursor >= input.length())
                break;
            if (hasEscape) {
                String decoded = decodeJavaEscapes(input.substring(start, cursor));
                if (decoded != null)
                    values.add(decoded);
            }
            index = cursor;
        }
        return values;
    }

    private static String decodeJavaEscapes(String input) {
        StringBuilder output = new StringBuilder(input.length());
        boolean changed = false;
        for (int index = 0; index < input.length();) {
            if (input.charAt(index) != '\\' || index + 1 >= input.length()) {
                output.append(input.charAt(index++));
                continue;
            }
            int end = readUnicodeEscape(input, index);
            if (end > 0) {
                char codeUnit = (char) Integer.parseInt(input.substring(end - 4, end), 16);
                changed = true;
                if (Character.isHighSurrogate(codeUnit)) {
                    int lowEnd = readUnicodeEscape(input, end);
                    if (lowEnd > 0) {
                        char low = (char) Integer.parseInt(input.substring(lowEnd - 4, lowEnd), 16);
                        if (Character.isLowSurrogate(low)) {
                            output.appendCodePoint(Character.toCodePoint(codeUnit, low));
                            index = lowEnd;
                            continue;
                        }
                    }
                    output.append(String.format("\\u%04X", (int) codeUnit));
                } else if (Character.isLowSurrogate(codeUnit)) {
                    output.append(String.format("\\u%04X", (int) codeUnit));
                } else {
                    output.append(codeUnit);
                }
                index = end;
                continue;
            }

            char escaped = input.charAt(index + 1);
            switch (escaped) {
                case 'b': output.append('\b'); break;
                case 't': output.append('\t'); break;
                case 'n': output.append('\n'); break;
                case 'f': output.append('\f'); break;
                case 'r': output.append('\r'); break;
                case '"': output.append('"'); break;
                case '\'': output.append('\''); break;
                case '\\': output.append('\\'); break;
                default:
                    output.append(input.charAt(index++));
                    continue;
            }
            changed = true;
            index += 2;
        }
        return changed ? output.toString() : null;
    }

    private static int readUnicodeEscape(String input, int start) {
        if (start + 2 > input.length() || input.charAt(start) != '\\' || input.charAt(start + 1) != 'u')
            return -1;
        int cursor = start + 1;
        while (cursor < input.length() && input.charAt(cursor) == 'u') cursor++;
        if (cursor + 4 > input.length())
            return -1;
        for (int index = cursor; index < cursor + 4; index++)
            if (hexValue(input.charAt(index)) < 0)
                return -1;
        return cursor + 4;
    }

    private static boolean isBase64Character(char value) {
        return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
            || value >= '0' && value <= '9' || value == '+' || value == '/' || value == '-'
            || value == '_' || value == '=';
    }

    private static int hexValue(char value) {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    }
}