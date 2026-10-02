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

using System.Text.Json.Serialization;
using System.Windows.Media;

namespace DeJavaEx.UI.Models;

public sealed record CallFinding(string ClassName, string MethodName, string Opcode, string Target, string Descriptor);
public sealed record ExtractedString(string Value, string Source);
public sealed record DecodedString(string Original, string Encoding, string Decoded, string Source);
public sealed record StaticFinding(string Category, string Evidence, string Source);
public sealed record SignalView(string Text, Brush Accent);

public sealed class NativeReport
{
    public string FileName { get; set; } = "";
    public string FilePath { get; set; } = "";
    public string FileType { get; set; } = "";
    public long SizeBytes { get; set; }
    public string Md5 { get; set; } = "";
    public string Sha1 { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public double Entropy { get; set; }
    public PackerReport? Packer { get; set; }
    public List<string> Classes { get; set; } = [];
    public List<ArchiveEntry> Entries { get; set; } = [];
    public List<ByteRegion> Regions { get; set; } = [];
    public List<string> Strings { get; set; } = [];
    public PeAnalysis? PeAnalysis { get; set; }
}

public sealed class PeAnalysis
{
    public string Architecture { get; set; } = "";
    public string Subsystem { get; set; } = "";
    public uint Timestamp { get; set; }
    public uint EntryPointRva { get; set; }
    public ulong ImageBase { get; set; }
    public ushort SectionCount { get; set; }
    public bool Is64Bit { get; set; }
    public bool IsDll { get; set; }
    public bool HasOverlay { get; set; }
    public ulong OverlayBytes { get; set; }
    public List<PeSection> Sections { get; set; } = [];
    public List<PeImport> Imports { get; set; } = [];
}

public sealed class PeSection
{
    public string Name { get; set; } = "";
    public uint VirtualAddress { get; set; }
    public uint VirtualSize { get; set; }
    public uint RawOffset { get; set; }
    public uint RawSize { get; set; }
    public uint Characteristics { get; set; }
    public double Entropy { get; set; }
    public bool Executable { get; set; }
    public bool Writable { get; set; }
}

public sealed class PeImport
{
    public string Module { get; set; } = "";
    public string Symbol { get; set; } = "";
    public bool ByOrdinal { get; set; }
    public ushort Ordinal { get; set; }
}

public sealed class PackerReport
{
    public string Verdict { get; set; } = "";
    public string Confidence { get; set; } = "";
    public string Level { get; set; } = "low";
    public List<string> Evidence { get; set; } = [];
}

public sealed class ArchiveEntry
{
    public string Path { get; set; } = "";
    public long Size { get; set; }
    public long CompressedSize { get; set; }
    public string Crc32 { get; set; } = "";
    public string Compression { get; set; } = "";
    public bool IsDirectory { get; set; }
}

public sealed class ByteRegion
{
    public int Index { get; set; }
    public long Offset { get; set; }
    public long Size { get; set; }
    public double Entropy { get; set; }
}

public sealed class JavaReport
{
    public string Status { get; set; } = "complete";
    public List<JavaCall> Calls { get; set; } = [];
    public List<JavaIndicator> Indicators { get; set; } = [];
    public List<string> PackerSignals { get; set; } = [];
    public List<JavaClassSummary> ClassAnalysis { get; set; } = [];
    public List<string> Strings { get; set; } = [];
    public List<DecodedString> DecodedStrings { get; set; } = [];
}

public sealed class JavaCall
{
    [JsonPropertyName("class")]
    public string ClassName { get; set; } = "";
    public string MethodName { get; set; } = "";
    public string Opcode { get; set; } = "";
    public string Owner { get; set; } = "";
    public string Target { get; set; } = "";
    [JsonPropertyName("target_descriptor")]
    public string TargetDescriptor { get; set; } = "";
}

public sealed class JavaClassSummary
{
    public string Name { get; set; } = "";
    public int MajorVersion { get; set; }
    public int MinorVersion { get; set; }
    public int MethodCount { get; set; }
    public int FieldCount { get; set; }
    public int ConstantTextCount { get; set; }
    public int CallCount { get; set; }
    public int DynamicCallCount { get; set; }
}

public sealed record JavaClassDetail(
    string Name,
    string ClassFileVersion,
    string JavaTarget,
    int MethodCount,
    int FieldCount,
    int CallCount,
    int DynamicCallCount);

public sealed record FileIndicator(string Type, string Value, string Source, string Context);

public sealed class FullFileAssessment
{
    public int Score { get; set; }
    public string Verdict { get; set; } = "Not assessed";
    public string Summary { get; set; } = "";
    public string Scope { get; set; } = "";
    public List<FileIndicator> Indicators { get; set; } = [];
    public List<StaticFinding> Evidence { get; set; } = [];
    public List<ExtractedString> ArchiveStrings { get; set; } = [];
}

public sealed class JavaIndicator
{
    public string Category { get; set; } = "";
    public string Evidence { get; set; } = "";
}