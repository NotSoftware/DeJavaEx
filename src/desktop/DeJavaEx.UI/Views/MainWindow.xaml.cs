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
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Xml;
using ICSharpCode.AvalonEdit.Highlighting;
using ICSharpCode.AvalonEdit.Highlighting.Xshd;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using Microsoft.Win32;
using DeJavaEx.UI.Models;
using DeJavaEx.UI.Services;
using IoPath = System.IO.Path;

namespace DeJavaEx.UI;

public partial class MainWindow : Window
{
    public ObservableCollection<ArchiveNode> ArchiveRoots { get; } = [];
    public ObservableCollection<string> DecompiledClasses { get; } = [];
    public ObservableCollection<ProjectNode> ProjectRoots { get; } = [];
    public ObservableCollection<CallFinding> Calls { get; } = [];
    public ObservableCollection<ExtractedString> Strings { get; } = [];
    public ObservableCollection<StaticFinding> Findings { get; } = [];

    private string? _selectedPath;
    private string? _projectRoot;
    private bool _closeAnimationRunning;
    private bool _allowClose;
    private readonly AnalysisEngineRunner _analysisEngine = new();
    private readonly ProjectWorkspaceService _projectWorkspace = new();

    public MainWindow()
    {
        Opacity = 0;
        InitializeComponent();
        DataContext = this;
        LoadJavaSyntaxHighlighting();
        FitToWorkingArea();
        DecompilerStatusText.Text = "Choose a class after analyzing a Java sample.";
        DecompiledSourceEditor.Text = "Choose a class after analyzing a Java sample.\n\nNo sample is currently loaded, so there is no reconstructed source to display.";
        UpdateSourcePlaceholder();
    }

    private void UpdateSourcePlaceholder()
    {
        var hasContent = !string.IsNullOrWhiteSpace(DecompiledSourceEditor.Text)
            && !string.Equals(DecompiledSourceEditor.Text.Trim(), "Choose a class after analyzing a Java sample.", StringComparison.Ordinal)
            && !string.Equals(DecompiledSourceEditor.Text.Trim(), "Choose a class after analyzing a Java sample.\n\nNo sample is currently loaded, so there is no reconstructed source to display.", StringComparison.Ordinal);
        SourcePlaceholderText.Visibility = hasContent ? Visibility.Collapsed : Visibility.Visible;
    }

    private void LoadJavaSyntaxHighlighting()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("DeJavaEx.UI.Views.JavaSyntax.xshd")
            ?? throw new InvalidOperationException("Java syntax highlighting definition is missing.");
        using var reader = XmlReader.Create(stream);
        DecompiledSourceEditor.SyntaxHighlighting = HighlightingLoader.Load(reader, HighlightingManager.Instance);
    }

    private void FitToWorkingArea()
    {
        var workArea = SystemParameters.WorkArea;
        Width = Math.Min(1380, workArea.Width * 0.94);
        Height = Math.Min(820, workArea.Height * 0.92);
        MinWidth = Math.Min(980, Width);
        MinHeight = Math.Min(620, Height);
        MaxWidth = workArea.Width;
        MaxHeight = workArea.Height;
        Left = workArea.Left + (workArea.Width - Width) / 2;
        Top = workArea.Top + (workArea.Height - Height) / 2;
    }

    private void OpenSample_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select a sample for static analysis",
            Filter = "Java artifacts (*.class;*.jar;*.war;*.ear)|*.class;*.jar;*.war;*.ear|All files (*.*)|*.*",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) == true)
            SelectSample(dialog.FileName);
    }

    private void SelectSample(string path)
    {
        _selectedPath = path;
        SelectedFileText.Text = path;
        AnalyzeButton.IsEnabled = true;
        StatusText.Text = "Sample selected · analysis has not started";
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        WorkspaceTabs.SelectedItem = AboutTab;
    }

    private void Overflow_Click(object sender, RoutedEventArgs e)
    {
        OverflowPopup.IsOpen = !OverflowPopup.IsOpen;
    }

    private void CreateProject_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Create a DeJavaEx project",
            Filter = "DeJavaEx project (*.dproj)|*.dproj",
            DefaultExt = ".dproj",
            AddExtension = true,
            FileName = "Java Analysis.dproj",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            OverwritePrompt = false
        };
        if (dialog.ShowDialog(this) != true)
            return;

        try
        {
            _projectRoot = _projectWorkspace.CreateProject(dialog.FileName);
            RefreshProject();
            StatusText.Text = $"Project created · {IoPath.GetFileName(_projectRoot)}";
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "Could not create project", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OpenProject_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open a DeJavaEx project",
            Filter = "DeJavaEx project (*.dproj)|*.dproj",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) != true)
            return;

        try
        {
            _projectRoot = _projectWorkspace.OpenProject(dialog.FileName);
            RefreshProject();
            StatusText.Text = $"Project opened · {IoPath.GetFileName(_projectRoot)}";
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "Could not open project", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void AddProjectFiles_Click(object sender, RoutedEventArgs e)
    {
        if (_projectRoot is null)
        {
            MessageBox.Show(this, "Create a project first, then add sample files to it.", "No project open", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new OpenFileDialog
        {
            Title = "Add samples to the current project",
            Filter = "Java artifacts (*.class;*.jar;*.war;*.ear)|*.class;*.jar;*.war;*.ear|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = true
        };
        if (dialog.ShowDialog(this) != true)
            return;

        try
        {
            var copied = _projectWorkspace.AddFiles(_projectRoot, dialog.FileNames);
            RefreshProject();
            StatusText.Text = $"Added {copied} sample file(s) to the project";
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "Could not add project files", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void RefreshProject_Click(object sender, RoutedEventArgs e) => RefreshProject();

    private void RefreshProject()
    {
        ProjectRoots.Clear();
        if (_projectRoot is null || !Directory.Exists(_projectRoot))
        {
            _projectRoot = null;
            ProjectNameText.Text = "No project open";
            return;
        }

        ProjectNameText.Text = IoPath.GetFileName(_projectRoot);
        ProjectRoots.Add(_projectWorkspace.LoadProject(_projectRoot));
    }

    private void ProjectTree_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ProjectTree.SelectedItem is ProjectNode { IsDirectory: false } node && IsSupportedSample(node.FullPath))
            SelectSample(node.FullPath);
    }

    private static bool IsSupportedSample(string path) =>
        IoPath.GetExtension(path).ToLowerInvariant() is ".class" or ".jar" or ".war" or ".ear";

    private async void Analyze_Click(object sender, RoutedEventArgs e)
    {
        var selectedPath = _selectedPath;
        if (selectedPath is null || !File.Exists(selectedPath))
            return;

        AnalyzeButton.IsEnabled = false;
        StatusText.Text = "Reading file bytes and analyzing archive structure…";
        AnalysisStateBadge.Text = "ANALYZING";
        try
        {
            var report = await _analysisEngine.AnalyzeAsync(selectedPath);
            RenderReport(report.Native, report.Java);
            StatusText.Text = $"Analysis complete · {IoPath.GetFileName(selectedPath)} · sample was not executed";
            AnalysisStateBadge.Text = "STATIC ANALYSIS COMPLETE";
            WorkspaceTabs.SelectedIndex = 0;
        }
        catch (Exception exception)
        {
            StatusText.Text = "Analysis failed · see details";
            AnalysisStateBadge.Text = "ANALYSIS ERROR";
            MessageBox.Show(this, exception.Message, "DeJavaEx analysis error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            AnalyzeButton.IsEnabled = _selectedPath is not null;
        }
    }

    private void RenderReport(NativeReport native, JavaReport? java)
    {
        SizeValue.Text = FormatSize(native.SizeBytes);
        FileTypeValue.Text = native.FileType;
        HashValue.Text = native.Sha256;
        HashValue.ToolTip = native.Sha256;
        EntropyValue.Text = $"{native.Entropy:F2} / 8";
        var javaPackerSignals = java?.PackerSignals ?? [];
        var hasJavaPackerSignals = javaPackerSignals.Count > 0;
        PackerValue.Text = hasJavaPackerSignals ? "Bytecode marker" : native.Packer?.Verdict ?? "Not assessed";
        PackerDetail.Text = hasJavaPackerSignals ? $"{javaPackerSignals.Count} Java constant-pool signals" : native.Packer?.Confidence ?? "No evidence returned";
        PackerValue.Foreground = hasJavaPackerSignals ? (Brush)FindResource("Coral") : native.Packer?.Level switch
        {
            "high" => (Brush)FindResource("Coral"),
            "medium" => (Brush)FindResource("Amber"),
            _ => (Brush)FindResource("Mint")
        };
        PackerConfidence.Text = hasJavaPackerSignals ? "BYTECODE SIGNATURE" : native.Packer?.Confidence.ToUpperInvariant() ?? "UNKNOWN";
        ArchiveSummary.Text = $"{native.Entries.Count:N0} ENTRIES  ·  {native.Classes.Count:N0} CLASS FILES";
        BytecodeStatusText.Text = java is null
            ? "The Java engine was unavailable; C++ file and archive analysis is still complete."
            : $"{java.ClassAnalysis.Count} classes · {java.ClassAnalysis.Sum(item => item.MethodCount):N0} methods · {java.ClassAnalysis.Sum(item => item.FieldCount):N0} fields · {java.Calls.Count:N0} bytecode refs · {java.ClassAnalysis.Sum(item => item.DynamicCallCount):N0} dynamic sites.";

        var packerEvidence = hasJavaPackerSignals ? javaPackerSignals : native.Packer?.Evidence ?? [];
        PackerSignalsList.ItemsSource = packerEvidence.Count > 0
            ? packerEvidence.Select(text => new SignalView(text, (Brush)FindResource(hasJavaPackerSignals || native.Packer?.Level == "high" ? "Coral" : "Amber"))).ToList()
            : [new SignalView("No known packer signature was identified.", (Brush)FindResource("Mint"))];

        ArchiveRoots.Clear();
        foreach (var node in BuildArchiveTree(native.Entries))
            ArchiveRoots.Add(node);

        Calls.Clear();
        foreach (var call in java?.Calls ?? [])
            Calls.Add(new CallFinding(call.ClassName, call.MethodName, call.Opcode, $"{call.Owner}.{call.Target}", call.TargetDescriptor));

        DecompiledClasses.Clear();
        var classNames = java is null
            ? Enumerable.Empty<string>()
            : java.ClassAnalysis.Select(item => item.Name).Distinct().OrderBy(name => name, StringComparer.OrdinalIgnoreCase);
        foreach (var className in classNames)
            DecompiledClasses.Add(className);
        DecompiledClassSelector.SelectedIndex = DecompiledClasses.Count > 0 ? 0 : -1;
        DecompileClassButton.IsEnabled = DecompiledClasses.Count > 0;
        DecompiledSourceEditor.Text = "Select a class and choose Decompile to reconstruct Java-like source from its bytecode.";
        DecompilerStatusText.Text = DecompiledClasses.Count > 0
            ? $"{DecompiledClasses.Count:N0} classes available · source reconstruction does not execute the sample."
            : "No Java classes were found in this sample.";

        Strings.Clear();
        var javaStrings = java?.Strings ?? [];
        foreach (var value in native.Strings.Select(value => (Value: value, Source: "C++ byte scan"))
                     .Concat(javaStrings.Select(value => (Value: value, Source: "Java constant pool")))
                     .DistinctBy(item => item.Value))
            Strings.Add(new ExtractedString(value.Value, value.Source));
        StringSummaryText.Text = $"{Strings.Count:N0} unique printable strings · native byte scan and Java class constant pools.";

        Findings.Clear();
        if (native.Packer is not null && native.Packer.Level != "low")
            foreach (var evidence in native.Packer.Evidence)
                Findings.Add(new StaticFinding("Packer / obfuscator signal", evidence, "C++ engine"));
        foreach (var signal in javaPackerSignals)
            Findings.Add(new StaticFinding("Packer / obfuscator signal", signal, "Java constant pool"));
        foreach (var indicator in java?.Indicators ?? [])
            Findings.Add(new StaticFinding(indicator.Category, indicator.Evidence, "Java bytecode"));
        if (native.Entropy >= 7.5)
            Findings.Add(new StaticFinding("High file entropy", $"Overall entropy is {native.Entropy:F3} bits per byte; this may indicate compression or encryption.", "C++ engine"));

        DrawByteMap(native.Regions);
    }

    private void DrawByteMap(IReadOnlyList<ByteRegion> regions)
    {
        ByteMapCanvas.Children.Clear();
        if (regions.Count == 0 || ByteMapCanvas.ActualWidth <= 0)
            return;

        var gap = 2.0;
        var width = (ByteMapCanvas.ActualWidth - gap * (regions.Count - 1)) / regions.Count;
        foreach (var region in regions)
        {
            var normalized = Math.Clamp(region.Entropy / 8.0, 0, 1);
            var color = normalized switch
            {
                < 0.42 => Color.FromRgb(42, 124, 97),
                < 0.68 => Color.FromRgb(115, 180, 123),
                < 0.84 => Color.FromRgb(225, 183, 91),
                _ => Color.FromRgb(238, 117, 92)
            };
            var rectangle = new Rectangle
            {
                Width = Math.Max(1, width),
                Height = ByteMapCanvas.ActualHeight,
                RadiusX = 2,
                RadiusY = 2,
                Fill = new SolidColorBrush(color),
                ToolTip = $"Offset 0x{region.Offset:X}\nSize {FormatSize(region.Size)}\nEntropy {region.Entropy:F2} bits/byte"
            };
            Canvas.SetLeft(rectangle, region.Index * (width + gap));
            ByteMapCanvas.Children.Add(rectangle);
        }
        MapEndLabel.Text = $"{regions[^1].Offset + regions[^1].Size:X8}";
    }

    private async void DecompileClass_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedPath is null || DecompiledClassSelector.SelectedItem is not string className)
            return;

        DecompileClassButton.IsEnabled = false;
        DecompilerStatusText.Text = $"Decompiling {className}…";
        try
        {
            var source = await _analysisEngine.DecompileClassAsync(_selectedPath, className);
            DecompiledSourceEditor.Text = source;
            UpdateSourcePlaceholder();
            DecompiledSourceEditor.Opacity = 0.72;
            DecompiledSourceEditor.BeginAnimation(OpacityProperty, new DoubleAnimation(0.72, 1, TimeSpan.FromMilliseconds(180))
            {
                EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
            });
            DecompilerStatusText.Text = $"Decompiled {className} · reconstructed source may differ from the original.";
        }
        catch (Exception exception)
        {
            DecompiledSourceEditor.Text = "Source reconstruction failed.";
            UpdateSourcePlaceholder();
            DecompilerStatusText.Text = exception.Message;
        }
        finally
        {
            DecompileClassButton.IsEnabled = DecompiledClasses.Count > 0;
        }
    }

    private void CopySource_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(DecompiledSourceEditor.Text))
            Clipboard.SetText(DecompiledSourceEditor.Text);
    }

    private void SaveSource_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(DecompiledSourceEditor.Text)
                || DecompiledClassSelector.SelectedItem is not string className)
            return;
        var dialog = new SaveFileDialog
        {
            Title = "Save reconstructed Java source",
            FileName = className[(className.LastIndexOf('.') + 1)..] + ".java",
            DefaultExt = ".java",
            AddExtension = true,
            Filter = "Java source (*.java)|*.java"
        };
        if (dialog.ShowDialog(this) == true)
            File.WriteAllText(dialog.FileName, DecompiledSourceEditor.Text, new System.Text.UTF8Encoding(false));
    }

    private static IEnumerable<ArchiveNode> BuildArchiveTree(IEnumerable<ArchiveEntry> entries)
    {
        var roots = new Dictionary<string, ArchiveNode>(StringComparer.Ordinal);
        var rootNodes = new List<ArchiveNode>();
        foreach (var entry in entries.OrderBy(item => item.Path, StringComparer.OrdinalIgnoreCase))
        {
            var parts = entry.Path.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
                continue;
            var current = roots;
            ICollection<ArchiveNode> childNodes = rootNodes;
            for (var index = 0; index < parts.Length; index++)
            {
                var isFile = index == parts.Length - 1 && !entry.IsDirectory;
                if (!current.TryGetValue(parts[index], out var node))
                {
                    node = new ArchiveNode(parts[index], isFile, isFile ? entry.Size : 0);
                    current.Add(parts[index], node);
                    childNodes.Add(node);
                }
                if (isFile)
                {
                    node.CompressedSize = entry.CompressedSize;
                    node.Compression = entry.Compression;
                }
                current = node.ChildMap;
                childNodes = node.Children;
            }
        }
        return rootNodes;
    }

    internal static string FormatSize(long size)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        double value = size;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return unit == 0 ? $"{size:N0} B" : $"{value:F2} {units[unit]}";
    }

    private void Navigate_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string indexText } && int.TryParse(indexText, out var index))
            WorkspaceTabs.SelectedIndex = index;
        else if (sender is Button button && int.TryParse(button.Tag?.ToString(), out index))
            WorkspaceTabs.SelectedIndex = index;
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(170))
        {
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
        });
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_allowClose)
            return;
        e.Cancel = true;
        if (_closeAnimationRunning)
            return;
        _closeAnimationRunning = true;
        var fade = new DoubleAnimation(Opacity, 0, TimeSpan.FromMilliseconds(130));
        fade.Completed += (_, _) =>
        {
            _allowClose = true;
            Close();
        };
        BeginAnimation(OpacityProperty, fade);
    }

    private void MinimizeWindow_Click(object sender, RoutedEventArgs e)
    {
        var fade = new DoubleAnimation(Opacity, 0.86, TimeSpan.FromMilliseconds(100));
        fade.Completed += (_, _) => WindowState = WindowState.Minimized;
        BeginAnimation(OpacityProperty, fade);
    }

    private void ToggleMaximize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        UpdateMaximizeButton();
        AnimateStateChange();
    }

    private void Window_StateChanged(object? sender, EventArgs e)
    {
        UpdateMaximizeButton();
        if (WindowState != WindowState.Minimized)
            AnimateStateChange();
    }

    private void AnimateStateChange()
    {
        BeginAnimation(OpacityProperty, new DoubleAnimation(0.94, 1, TimeSpan.FromMilliseconds(130))
        {
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut }
        });
    }

    private void UpdateMaximizeButton()
    {
        MaximizeWindowButton.ToolTip = WindowState == WindowState.Maximized ? "Restore" : "Maximize";
        MaximizeWindowButton.Content = WindowState == WindowState.Maximized ? "❐" : "□";
    }

    private void CloseWindow_Click(object sender, RoutedEventArgs e) => Close();

    private void DismissWelcome_Click(object sender, RoutedEventArgs e) => WelcomeOverlay.Visibility = Visibility.Collapsed;

    private void Window_DragOver(object sender, DragEventArgs e) => e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;

    private void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is not string[] files || files.Length == 0 || !File.Exists(files[0]))
            return;
        SelectSample(files[0]);
    }
}

