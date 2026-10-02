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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

public final class StaticAnalyzer {
    static final int MAX_CLASS_BYTES = 64 * 1024 * 1024;
    private static final int MAX_NESTED_ARCHIVE_BYTES = 256 * 1024 * 1024;
    private static final int MAX_ARCHIVE_CLASSES = 100000;

    private StaticAnalyzer() {}

    public static void main(String[] args) {
        if (args.length == 2 && "--decode-strings".equals(args[0])) {
            try {
                JsonReportWriter.writeDecodedStrings(StringDecoder.decodeRequestFile(Path.of(args[1])));
            } catch (Exception exception) {
                System.err.println("String decoding failed: " + exception.getMessage());
                System.exit(1);
            }
            return;
        }
        if (args.length != 1) {
            System.err.println("Usage: StaticAnalyzer <class-or-jar-war-ear>");
            System.exit(2);
        }
        try {
            analyze(Path.of(args[0]));
        } catch (Exception exception) {
            System.err.println("Static analysis failed: " + exception.getMessage());
            System.exit(1);
        }
    }

    private static void analyze(Path input) throws IOException {
        List<String> classes = new ArrayList<>();
        Set<String> strings = new TreeSet<>();
        List<Call> calls = new ArrayList<>();
        List<ClassSummary> classAnalysis = new ArrayList<>();
        Map<String, LinkedHashSet<String>> indicators = new TreeMap<>();
        Set<String> packerSignals = new TreeSet<>();

        if (isArchive(input))
            analyzeArchive(input, classes, strings, calls, classAnalysis, indicators, packerSignals);
        else
            addClass(Files.readAllBytes(input), input.getFileName().toString(), classes, calls,
                classAnalysis, indicators, packerSignals, strings);

        JsonReportWriter.write(classes, calls, classAnalysis, indicators, packerSignals, strings,
            StringDecoder.decode(strings, "Java constant pool"));
    }

    private static boolean isArchive(Path input) {
        String extension = input.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
        return extension.endsWith(".jar") || extension.endsWith(".zip")
            || extension.endsWith(".war") || extension.endsWith(".ear")
            || extension.endsWith(".apk");
    }

    private static void analyzeArchive(Path path, List<String> classes, Set<String> strings, List<Call> calls,
            List<ClassSummary> classAnalysis, Map<String, LinkedHashSet<String>> indicators,
            Set<String> packerSignals) throws IOException {
        try (ZipFile archive = new ZipFile(path.toFile())) {
            Enumeration<? extends ZipEntry> entries = archive.entries();
            while (entries.hasMoreElements() && classes.size() < MAX_ARCHIVE_CLASSES) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory())
                    continue;
                String name = entry.getName();
                if (name.endsWith(".class") && entry.getSize() <= MAX_CLASS_BYTES) {
                    try (InputStream stream = archive.getInputStream(entry)) {
                        byte[] bytes = readLimited(stream, MAX_CLASS_BYTES);
                        if (bytes != null)
                            addClass(bytes, name, classes, calls, classAnalysis, indicators, packerSignals, strings);
                    }
                } else if (name.toLowerCase(java.util.Locale.ROOT).endsWith(".jar")
                        && entry.getSize() <= MAX_NESTED_ARCHIVE_BYTES) {
                    try (InputStream stream = archive.getInputStream(entry)) {
                        byte[] nestedArchive = readLimited(stream, MAX_NESTED_ARCHIVE_BYTES);
                        if (nestedArchive != null)
                            analyzeNestedArchive(nestedArchive, name, classes, calls, classAnalysis, indicators, packerSignals, strings);
                    }
                }
            }
        }
    }

    private static void analyzeNestedArchive(byte[] archiveBytes, String archiveName, List<String> classes,
            List<Call> calls, List<ClassSummary> classAnalysis, Map<String, LinkedHashSet<String>> indicators,
            Set<String> packerSignals, Set<String> strings) throws IOException {
        try (ZipInputStream archive = new ZipInputStream(new java.io.ByteArrayInputStream(archiveBytes))) {
            ZipEntry entry;
            while ((entry = archive.getNextEntry()) != null && classes.size() < MAX_ARCHIVE_CLASSES) {
                if (entry.isDirectory() || !entry.getName().endsWith(".class"))
                    continue;
                byte[] classBytes = readLimited(archive, MAX_CLASS_BYTES);
                if (classBytes != null)
                    addClass(classBytes, archiveName + "!/" + entry.getName(), classes, calls,
                        classAnalysis, indicators, packerSignals, strings);
            }
        }
    }

    private static byte[] readLimited(InputStream stream, int maximumBytes) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int count;
        while ((count = stream.read(buffer)) != -1) {
            if (bytes.size() + count > maximumBytes)
                return null;
            bytes.write(buffer, 0, count);
        }
        return bytes.toByteArray();
    }

    private static void addClass(byte[] bytes, String fallbackName, List<String> classes, List<Call> calls,
            List<ClassSummary> classAnalysis, Map<String, LinkedHashSet<String>> indicators,
            Set<String> packerSignals, Set<String> strings) throws IOException {
        if (bytes.length > MAX_CLASS_BYTES)
            return;
        ClassFileReader reader = new ClassFileReader(bytes, fallbackName, calls, indicators, packerSignals, strings);
        ClassSummary summary = reader.read();
        classes.add(summary.name);
        classAnalysis.add(summary);
    }

    static void addIndicator(Map<String, LinkedHashSet<String>> indicators, String category, String evidence) {
        indicators.computeIfAbsent(category, ignored -> new LinkedHashSet<>()).add(evidence);
    }

    static String indicatorCategory(String owner, String target) {
        owner = owner.replace('.', '/');
        if ((owner.equals("java/lang/Runtime") && target.equals("exec"))
                || (owner.equals("java/lang/ProcessBuilder") && target.equals("start"))) return "Process execution";
        if (owner.contains("ClassLoader") && (target.equals("defineClass") || target.equals("loadClass"))) return "Dynamic class loading";
        if (owner.startsWith("java/net/")) return "Network access";
        if (owner.equals("java/lang/Class") && target.equals("forName")) return "Dynamic class loading";
        if (owner.startsWith("java/lang/reflect/") && (target.equals("invoke") || target.equals("setAccessible"))) return "Reflection";
        if (owner.equals("javax/crypto/Cipher") && (target.equals("getInstance") || target.equals("doFinal"))) return "Cryptography";
        if (owner.equals("java/lang/System") && (target.equals("load") || target.equals("loadLibrary"))) return "Native library loading";
        if (owner.startsWith("java/io/") && (target.contains("Stream") || target.equals("delete"))) return "File system access";
        return null;
    }

    static void detectPackerMarkers(Object[] pool, Set<String> packerSignals) {
        String[] markers = {"allatori", "zelix", "zkm", "stringer", "dasho", "skidfuscator",
            "jshield", "jpack", "proguard", "yguard", "jshrink", "pack200"};
        for (Object value : pool) {
            if (!(value instanceof String)) continue;
            String lowered = ((String) value).toLowerCase(java.util.Locale.ROOT);
            for (String marker : markers) {
                if (lowered.contains(marker)) packerSignals.add("Tooling marker: " + marker);
            }
        }
    }

    static final class ClassSummary {
        final String name;
        final int majorVersion;
        final int minorVersion;
        final int methodCount;
        final int fieldCount;
        final int constantTextCount;
        final int callCount;
        final int dynamicCallCount;

        ClassSummary(String name, int majorVersion, int minorVersion, int methodCount, int fieldCount,
            int constantTextCount, int callCount, int dynamicCallCount) {
            this.name = name;
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;
            this.methodCount = methodCount;
            this.fieldCount = fieldCount;
            this.constantTextCount = constantTextCount;
            this.callCount = callCount;
            this.dynamicCallCount = dynamicCallCount;
        }
    }

    static final class Call {
        final String className;
        final String methodName;
        final String methodDescriptor;
        final String opcode;
        final String owner;
        final String targetName;
        final String targetDescriptor;

        Call(String className, String methodName, String methodDescriptor, String opcode,
                String owner, String targetName, String targetDescriptor) {
            this.className = className;
            this.methodName = methodName;
            this.methodDescriptor = methodDescriptor;
            this.opcode = opcode;
            this.owner = owner;
            this.targetName = targetName;
            this.targetDescriptor = targetDescriptor;
        }
    }
}
