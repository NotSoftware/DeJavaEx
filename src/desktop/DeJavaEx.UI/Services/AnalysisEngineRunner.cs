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

using System.Diagnostics;
using System.IO.Compression;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;
using DeJavaEx.UI.Models;
using IoPath = System.IO.Path;

namespace DeJavaEx.UI.Services;

internal sealed class AnalysisEngineRunner
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public async Task<AnalysisRunResult> AnalyzeAsync(string path)
    {
        var native = await RunNativeEngineAsync(path);
        var java = await RunJavaEngineAsync(path);
        return new AnalysisRunResult(native, java);
    }

    public async Task<string> DecompileClassAsync(string samplePath, string className)
    {
        var java = FindJavaRuntime() ?? throw new InvalidOperationException("Install a Java runtime to decompile bytecode.");
        var decompiler = ExtractResource("DeJavaEx.cfr-0.152.jar", "cfr-0.152.jar");
        var workDirectory = IoPath.Combine(IoPath.GetTempPath(), "DeJavaEx", Guid.NewGuid().ToString("N"));
        var outputDirectory = IoPath.Combine(workDirectory, "source");
        Directory.CreateDirectory(outputDirectory);
        try
        {
            var classFile = IoPath.Combine(workDirectory, "selected.class");
            var classBytes = ReadSelectedClass(samplePath, className);
            await File.WriteAllBytesAsync(classFile, classBytes);
            await RunProcessAsync(java, ["-jar", decompiler, classFile, "--outputdir", outputDirectory, "--silent", "true"]);

            var sourceFiles = Directory.EnumerateFiles(outputDirectory, "*.java", SearchOption.AllDirectories).ToList();
            var expectedName = className[(className.LastIndexOf('.') + 1)..];
            var sourceFile = sourceFiles.FirstOrDefault(file => string.Equals(
                IoPath.GetFileNameWithoutExtension(file), expectedName, StringComparison.Ordinal)) ?? sourceFiles.FirstOrDefault();
            if (sourceFile is null)
                throw new InvalidDataException("CFR did not produce Java source for the selected class.");
            if (new FileInfo(sourceFile).Length > 16 * 1024 * 1024)
                throw new InvalidDataException("The decompiled source exceeds the 16 MiB display limit.");
            return await File.ReadAllTextAsync(sourceFile, Encoding.UTF8);
        }
        finally
        {
            if (Directory.Exists(workDirectory))
                Directory.Delete(workDirectory, recursive: true);
        }
    }

    private static byte[] ReadSelectedClass(string samplePath, string className)
    {
        const int maximumClassBytes = 64 * 1024 * 1024;
        var extension = IoPath.GetExtension(samplePath);
        if (string.Equals(extension, ".class", StringComparison.OrdinalIgnoreCase))
        {
            var bytes = File.ReadAllBytes(samplePath);
            if (bytes.Length > maximumClassBytes)
                throw new InvalidDataException("The class file exceeds the 64 MiB decompilation limit.");
            return bytes;
        }

        var entryName = className.Replace('.', '/') + ".class";
        using var archive = ZipFile.OpenRead(samplePath);
        var directEntry = archive.GetEntry(entryName);
        if (directEntry is not null)
            return ReadClassEntry(directEntry, maximumClassBytes);

        foreach (var nestedEntry in archive.Entries.Where(entry => entry.FullName.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)))
        {
            if (nestedEntry.Length > 256L * 1024 * 1024)
                continue;
            using var nestedStream = nestedEntry.Open();
            using var nestedBytes = new MemoryStream();
            CopyLimited(nestedStream, nestedBytes, 256L * 1024 * 1024);
            nestedBytes.Position = 0;
            using var nestedArchive = new ZipArchive(nestedBytes, ZipArchiveMode.Read, leaveOpen: false);
            var classEntry = nestedArchive.GetEntry(entryName);
            if (classEntry is not null)
                return ReadClassEntry(classEntry, maximumClassBytes);
        }
        throw new FileNotFoundException($"Could not find {entryName} in the selected archive.");
    }

    private static byte[] ReadClassEntry(ZipArchiveEntry entry, int maximumBytes)
    {
        if (entry.Length > maximumBytes)
            throw new InvalidDataException("The selected class exceeds the 64 MiB decompilation limit.");
        using var input = entry.Open();
        using var output = new MemoryStream();
        CopyLimited(input, output, maximumBytes);
        return output.ToArray();
    }

    private static void CopyLimited(Stream input, Stream output, long maximumBytes)
    {
        var buffer = new byte[8192];
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) != 0)
        {
            if (output.Length + read > maximumBytes)
                throw new InvalidDataException("An archive entry exceeds the configured analysis size limit.");
            output.Write(buffer, 0, read);
        }
    }

    private static async Task<NativeReport> RunNativeEngineAsync(string path)
    {
        var enginePath = ExtractResource("DeJavaEx.dejavaex-engine.exe", "dejavaex-engine.exe");
        var result = await RunProcessAsync(enginePath, [path]);
        return JsonSerializer.Deserialize<NativeReport>(result, JsonOptions)
            ?? throw new InvalidDataException("The C++ engine returned an empty report.");
    }

    private static async Task<JavaReport?> RunJavaEngineAsync(string path)
    {
        if (!string.Equals(IoPath.GetExtension(path), ".class", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(IoPath.GetExtension(path), ".jar", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(IoPath.GetExtension(path), ".war", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(IoPath.GetExtension(path), ".ear", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(IoPath.GetExtension(path), ".zip", StringComparison.OrdinalIgnoreCase))
            return new JavaReport { Status = "Not a Java class or archive" };

        var java = FindJavaRuntime();
        if (java is null)
            return new JavaReport { Status = "Java runtime not found" };

        var javaArchive = ExtractResource("DeJavaEx.java-engine.jar", "dejavaex-java-engine.jar");
        var json = await RunProcessAsync(java, ["-jar", javaArchive, path]);
        return JsonSerializer.Deserialize<JavaReport>(json, JsonOptions)
            ?? throw new InvalidDataException("The Java engine returned an empty report.");
    }

    private static string? FindJavaRuntime()
    {
        var javaHome = Environment.GetEnvironmentVariable("JAVA_HOME");
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(javaHome))
            candidates.Add(IoPath.Combine(javaHome, "bin", "java.exe"));
        var pathJava = Environment.GetEnvironmentVariable("PATH")?.Split(IoPath.PathSeparator)
            .Select(directory => IoPath.Combine(directory.Trim('"'), "java.exe")) ?? [];
        candidates.AddRange(pathJava);
        return candidates.FirstOrDefault(File.Exists);
    }

    private static async Task<string> RunProcessAsync(string executable, IReadOnlyList<string> arguments)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException($"Could not start {IoPath.GetFileName(executable)}.");
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        var output = await outputTask;
        var error = await errorTask;
        if (process.ExitCode != 0)
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(error)
                ? $"{IoPath.GetFileName(executable)} exited with code {process.ExitCode}."
                : error.Trim());
        return output;
    }

    private static string ExtractResource(string resourceName, string outputName)
    {
        using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName)
            ?? throw new FileNotFoundException($"Embedded analysis engine is missing: {resourceName}. Rebuild DeJavaEx using build.ps1.");
        var directory = IoPath.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DeJavaEx", "engines");
        Directory.CreateDirectory(directory);
        var destination = IoPath.Combine(directory, outputName);
        using var target = File.Create(destination);
        resource.CopyTo(target);
        return destination;
    }
}

internal sealed record AnalysisRunResult(NativeReport Native, JavaReport? Java);