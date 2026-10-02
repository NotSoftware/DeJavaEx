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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class ClassFileReader {
    private final DataInputStream input;
    private final String fallbackName;
    private final List<StaticAnalyzer.Call> calls;
    private final Map<String, LinkedHashSet<String>> indicators;
    private final Set<String> packerSignals;
    private final Set<String> strings;
    private Object[] pool;
    private String className;
    private int majorVersion;
    private int minorVersion;
    private int methodCount;
    private int fieldCount;
    private int dynamicCallCount;
    private int constantTextCount;

    ClassFileReader(byte[] bytes, String name, List<StaticAnalyzer.Call> foundCalls,
            Map<String, LinkedHashSet<String>> foundIndicators, Set<String> foundPackerSignals,
            Set<String> foundStrings) {
        input = new DataInputStream(new ByteArrayInputStream(bytes));
        fallbackName = name;
        calls = foundCalls;
        indicators = foundIndicators;
        packerSignals = foundPackerSignals;
        strings = foundStrings;
    }

    StaticAnalyzer.ClassSummary read() throws IOException {
        if (input.readInt() != 0xCAFEBABE)
            throw new IOException("Invalid class file: " + fallbackName);
        minorVersion = input.readUnsignedShort();
        majorVersion = input.readUnsignedShort();
        readConstantPool();
        collectConstantStrings();
        StaticAnalyzer.detectPackerMarkers(pool, packerSignals);
        input.readUnsignedShort();
        int thisClass = input.readUnsignedShort();
        input.readUnsignedShort();
        className = className(thisClass);
        int interfaces = input.readUnsignedShort();
        skipFully(input, interfaces * 2L);
        fieldCount = readFieldCount(input);
        int firstCall = calls.size();
        int firstDynamicCall = dynamicCallCount;
        readMethods();
        skipAttributes(input);
        if (className.matches("([A-Za-z0-9_$]{1,2}\\.){2,}[A-Za-z0-9_$]{1,2}"))
            packerSignals.add("Short package and class names: " + className);
        return new StaticAnalyzer.ClassSummary(className, majorVersion, minorVersion, methodCount,
            fieldCount, constantTextCount, calls.size() - firstCall, dynamicCallCount - firstDynamicCall);
    }

    private void collectConstantStrings() {
        for (Object value : pool) {
            if (value instanceof String) {
                constantTextCount++;
                String text = (String) value;
                if (text.length() >= 5 && strings.size() < 10000)
                    strings.add(text);
            }
        }
    }

    private void readConstantPool() throws IOException {
        int count = input.readUnsignedShort();
        pool = new Object[count];
        for (int index = 1; index < count; index++) {
            int tag = input.readUnsignedByte();
            switch (tag) {
                case 1: pool[index] = input.readUTF(); break;
                case 3: case 4: skipFully(input, 4); break;
                case 5: case 6: skipFully(input, 8); index++; break;
                case 7: pool[index] = new ClassInfo(input.readUnsignedShort()); break;
                case 8: case 16: case 19: case 20: skipFully(input, 2); break;
                case 9: case 10: case 11:
                    pool[index] = new MemberRef(tag, input.readUnsignedShort(), input.readUnsignedShort()); break;
                case 12: pool[index] = new NameAndType(input.readUnsignedShort(), input.readUnsignedShort()); break;
                case 15: skipFully(input, 3); break;
                case 17: skipFully(input, 4); break;
                case 18: pool[index] = new DynamicCall(input.readUnsignedShort(), input.readUnsignedShort()); break;
                default: throw new IOException("Unsupported constant-pool tag " + tag);
            }
        }
    }

    private int readFieldCount(DataInputStream stream) throws IOException {
        int count = stream.readUnsignedShort();
        for (int member = 0; member < count; member++) {
            stream.readUnsignedShort();
            stream.readUnsignedShort();
            stream.readUnsignedShort();
            skipAttributes(stream);
        }
        return count;
    }

    private void readMethods() throws IOException {
        int count = input.readUnsignedShort();
        methodCount = count;
        for (int method = 0; method < count; method++) {
            input.readUnsignedShort();
            String name = utf8(input.readUnsignedShort());
            String descriptor = utf8(input.readUnsignedShort());
            int attributes = input.readUnsignedShort();
            for (int attribute = 0; attribute < attributes; attribute++) {
                String attributeName = utf8(input.readUnsignedShort());
                int length = input.readInt();
                if (length < 0 || length > StaticAnalyzer.MAX_CLASS_BYTES)
                    throw new IOException("Invalid method attribute length");
                byte[] body = input.readNBytes(length);
                if (body.length != length)
                    throw new IOException("Truncated method attribute");
                if ("Code".equals(attributeName))
                    readCode(body, name, descriptor);
            }
        }
    }

    private void readCode(byte[] body, String methodName, String methodDescriptor) throws IOException {
        DataInputStream codeAttribute = new DataInputStream(new ByteArrayInputStream(body));
        codeAttribute.readUnsignedShort();
        codeAttribute.readUnsignedShort();
        int length = codeAttribute.readInt();
        if (length < 0 || length > body.length)
            return;
        byte[] code = codeAttribute.readNBytes(length);
        if (code.length == length)
            scanInstructions(code, methodName, methodDescriptor);
    }

    private void scanInstructions(byte[] code, String methodName, String descriptor) {
        int pc = 0;
        while (pc < code.length) {
            int opcode = code[pc] & 0xff;
            int instructionLength = instructionLength(code, pc, opcode);
            if (instructionLength <= 0 || pc + instructionLength > code.length)
                return;
            if (opcode >= 0xb2 && opcode <= 0xb9)
                addCall(unsignedShort(code, pc + 1), methodName, descriptor, opcodeName(opcode));
            else if (opcode == 0xba)
                addDynamicCall(unsignedShort(code, pc + 1), methodName, descriptor);
            pc += instructionLength;
        }
    }

    private void addCall(int index, String methodName, String descriptor, String opcode) {
        if (index <= 0 || index >= pool.length || !(pool[index] instanceof MemberRef))
            return;
        MemberRef reference = (MemberRef) pool[index];
        if (reference.classIndex >= pool.length || reference.nameAndTypeIndex >= pool.length
                || !(pool[reference.nameAndTypeIndex] instanceof NameAndType))
            return;
        NameAndType nameType = (NameAndType) pool[reference.nameAndTypeIndex];
        String owner = className(reference.classIndex);
        String target = utf8(nameType.nameIndex);
        calls.add(new StaticAnalyzer.Call(className, methodName, descriptor, opcode, owner,
            target, utf8(nameType.descriptorIndex)));
        String category = StaticAnalyzer.indicatorCategory(owner, target);
        if (category != null)
            StaticAnalyzer.addIndicator(indicators, category, owner + "." + target);
    }

    private void addDynamicCall(int index, String methodName, String descriptor) {
        if (index <= 0 || index >= pool.length || !(pool[index] instanceof DynamicCall))
            return;
        DynamicCall dynamic = (DynamicCall) pool[index];
        if (dynamic.nameAndTypeIndex <= 0 || dynamic.nameAndTypeIndex >= pool.length
                || !(pool[dynamic.nameAndTypeIndex] instanceof NameAndType))
            return;
        NameAndType nameType = (NameAndType) pool[dynamic.nameAndTypeIndex];
        String target = utf8(nameType.nameIndex);
        calls.add(new StaticAnalyzer.Call(className, methodName, descriptor, "invokedynamic",
            "bootstrap#" + dynamic.bootstrapIndex, target, utf8(nameType.descriptorIndex)));
        StaticAnalyzer.addIndicator(indicators, "Dynamic invocation", className + "." + methodName + " -> " + target);
        dynamicCallCount++;
    }

    private int instructionLength(byte[] code, int pc, int opcode) {
        if (opcode == 0xaa || opcode == 0xab) {
            int padding = (4 - ((pc + 1) & 3)) & 3;
            int cursor = pc + 1 + padding;
            if (cursor + (opcode == 0xaa ? 12 : 8) > code.length)
                return -1;
            if (opcode == 0xaa) {
                int low = signedInt(code, cursor + 4);
                int high = signedInt(code, cursor + 8);
                long length = 1L + padding + 12L + 4L * ((long) high - low + 1L);
                return length > Integer.MAX_VALUE ? -1 : (int) length;
            }
            int pairs = signedInt(code, cursor + 4);
            long length = 1L + padding + 8L + 8L * pairs;
            return pairs < 0 || length > Integer.MAX_VALUE ? -1 : (int) length;
        }
        if (opcode == 0xc4)
            return pc + 1 < code.length && (code[pc + 1] & 0xff) == 0x84 ? 6 : 4;
        if (opcode == 0x10 || opcode == 0x12 || (opcode >= 0x15 && opcode <= 0x19)
                || (opcode >= 0x36 && opcode <= 0x3a) || opcode == 0xa9 || opcode == 0xbc)
            return 2;
        if (opcode == 0x11 || opcode == 0x13 || opcode == 0x14 || opcode == 0x84
            || (opcode >= 0xb2 && opcode <= 0xb8)
                || (opcode >= 0x99 && opcode <= 0xa8) || opcode == 0xc6 || opcode == 0xc7
            || opcode == 0xbb || opcode == 0xbd
                || opcode == 0xc0 || opcode == 0xc1)
            return 3;
        if (opcode == 0xb9 || opcode == 0xba || opcode == 0xc8 || opcode == 0xc9)
            return 5;
        if (opcode == 0xc5)
            return 4;
        return 1;
    }

    private String className(int index) {
        if (index <= 0 || index >= pool.length || !(pool[index] instanceof ClassInfo))
            return fallbackName;
        return utf8(((ClassInfo) pool[index]).nameIndex).replace('/', '.');
    }

    private String utf8(int index) {
        return index > 0 && index < pool.length && pool[index] instanceof String ? (String) pool[index] : "?";
    }

    private static int unsignedShort(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    private static int signedInt(byte[] bytes, int offset) {
        return (bytes[offset] << 24) | ((bytes[offset + 1] & 0xff) << 16)
            | ((bytes[offset + 2] & 0xff) << 8) | (bytes[offset + 3] & 0xff);
    }

    private static void skipAttributes(DataInputStream stream) throws IOException {
        int count = stream.readUnsignedShort();
        for (int attribute = 0; attribute < count; attribute++) {
            stream.readUnsignedShort();
            long length = Integer.toUnsignedLong(stream.readInt());
            skipFully(stream, length);
        }
    }

    private static void skipFully(DataInputStream stream, long length) throws IOException {
        while (length > 0) {
            int skipped = stream.skipBytes((int) Math.min(length, Integer.MAX_VALUE));
            if (skipped <= 0)
                throw new IOException("Truncated class file");
            length -= skipped;
        }
    }

    private static String opcodeName(int opcode) {
        switch (opcode) {
            case 0xb2: return "getstatic";
            case 0xb3: return "putstatic";
            case 0xb4: return "getfield";
            case 0xb5: return "putfield";
            case 0xb6: return "invokevirtual";
            case 0xb7: return "invokespecial";
            case 0xb8: return "invokestatic";
            case 0xb9: return "invokeinterface";
            default: return "invoke";
        }
    }

    private static final class ClassInfo {
        final int nameIndex;
        ClassInfo(int value) { nameIndex = value; }
    }

    private static final class NameAndType {
        final int nameIndex;
        final int descriptorIndex;
        NameAndType(int name, int descriptor) { nameIndex = name; descriptorIndex = descriptor; }
    }

    private static final class MemberRef {
        final int tag;
        final int classIndex;
        final int nameAndTypeIndex;
        MemberRef(int type, int owner, int nameType) {
            tag = type;
            classIndex = owner;
            nameAndTypeIndex = nameType;
        }
    }

    private static final class DynamicCall {
        final int bootstrapIndex;
        final int nameAndTypeIndex;
        DynamicCall(int bootstrap, int nameAndType) {
            bootstrapIndex = bootstrap;
            nameAndTypeIndex = nameAndType;
        }
    }
}