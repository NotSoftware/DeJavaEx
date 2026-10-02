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

using System.Collections.ObjectModel;
using System.Windows.Media;
using DeJavaEx.UI;

namespace DeJavaEx.UI.Models;

public sealed class ArchiveNode(string name, bool isFile, long size)
{
    public string Name { get; } = name;
    public bool IsFile { get; } = isFile;
    public long Size { get; } = size;
    public long CompressedSize { get; set; }
    public string Compression { get; set; } = "";
    public ObservableCollection<ArchiveNode> Children { get; } = [];
    internal Dictionary<string, ArchiveNode> ChildMap { get; } = new(StringComparer.Ordinal);
    public string Glyph => IsFile ? "·" : "▾";
    public string SizeLabel => IsFile ? $"{MainWindow.FormatSize(Size)}{(Compression.Length > 0 ? $"  ·  {Compression}" : "")}" : "";
    public Brush Accent => IsFile ? Brushes.LightGray : new SolidColorBrush(Color.FromRgb(118, 228, 188));
}