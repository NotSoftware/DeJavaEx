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

using System.IO;
using System.Text.Json;
using DeJavaEx.UI.Models;

namespace DeJavaEx.UI.Services;

internal sealed class ProjectWorkspaceService
{
    private const int MaximumItems = 5000;
    private const int MaximumDepth = 12;

    public string CreateProject(string projectFilePath)
    {
        var projectName = Path.GetFileNameWithoutExtension(projectFilePath);
        var parentDirectory = Path.GetDirectoryName(Path.GetFullPath(projectFilePath))
            ?? throw new InvalidOperationException("Choose a valid project location.");
        var projectRoot = Path.Combine(parentDirectory, projectName);
        if (Directory.Exists(projectRoot) || File.Exists(projectFilePath))
            throw new IOException("A project with that name already exists.");

        Directory.CreateDirectory(Path.Combine(projectRoot, "Samples"));
        var projectFile = Path.Combine(projectRoot, Path.GetFileName(projectFilePath));
        var metadata = new { Name = projectName, Version = 1 };
        File.WriteAllText(projectFile, JsonSerializer.Serialize(metadata));
        return projectRoot;
    }

    public string OpenProject(string projectFilePath)
    {
        if (!string.Equals(Path.GetExtension(projectFilePath), ".dproj", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Select a DeJavaEx .dproj file.");
        if (!File.Exists(projectFilePath))
            throw new FileNotFoundException("The project file does not exist.", projectFilePath);

        using var metadata = JsonDocument.Parse(File.ReadAllText(projectFilePath));
        if (!metadata.RootElement.TryGetProperty("Version", out var version) || version.GetInt32() != 1
                || !metadata.RootElement.TryGetProperty("Name", out var name)
                || name.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("The selected file is not a valid DeJavaEx project.");
        var projectRoot = Path.GetDirectoryName(Path.GetFullPath(projectFilePath))
            ?? throw new InvalidDataException("The project path is invalid.");
        if (!string.Equals(name.GetString(), Path.GetFileName(projectRoot), StringComparison.Ordinal))
            throw new InvalidDataException("The project name does not match its folder.");
        return projectRoot;
    }

    public int AddFiles(string projectRoot, IEnumerable<string> sourcePaths)
    {
        var samplesPath = Path.Combine(projectRoot, "Samples");
        Directory.CreateDirectory(samplesPath);
        var copied = 0;
        foreach (var sourcePath in sourcePaths)
        {
            if (!File.Exists(sourcePath))
                continue;
            var destination = GetUniquePath(samplesPath, Path.GetFileName(sourcePath));
            File.Copy(sourcePath, destination);
            copied++;
        }
        return copied;
    }

    public ProjectNode LoadProject(string projectRoot)
    {
        var root = new DirectoryInfo(projectRoot);
        var tree = new ProjectNode(root.Name, root.FullName, true);
        var itemCount = 0;
        Populate(tree, root, 0, ref itemCount);
        return tree;
    }

    private static void Populate(ProjectNode parent, DirectoryInfo directory, int depth, ref int itemCount)
    {
        if (depth >= MaximumDepth || itemCount >= MaximumItems)
            return;

        IEnumerable<FileSystemInfo> entries;
        try
        {
            entries = directory.EnumerateFileSystemInfos()
                .Where(entry => (entry.Attributes & FileAttributes.ReparsePoint) == 0)
                .OrderByDescending(entry => (entry.Attributes & FileAttributes.Directory) != 0)
                .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }
        catch (IOException)
        {
            return;
        }

        foreach (var entry in entries)
        {
            if (itemCount >= MaximumItems)
                break;
            var isDirectory = (entry.Attributes & FileAttributes.Directory) != 0;
            var child = new ProjectNode(entry.Name, entry.FullName, isDirectory);
            parent.Children.Add(child);
            itemCount++;
            if (isDirectory)
                Populate(child, (DirectoryInfo)entry, depth + 1, ref itemCount);
        }
    }

    private static string GetUniquePath(string directory, string fileName)
    {
        var candidate = Path.Combine(directory, fileName);
        var name = Path.GetFileNameWithoutExtension(fileName);
        var extension = Path.GetExtension(fileName);
        var suffix = 2;
        while (File.Exists(candidate))
            candidate = Path.Combine(directory, $"{name} ({suffix++}){extension}");
        return candidate;
    }
}