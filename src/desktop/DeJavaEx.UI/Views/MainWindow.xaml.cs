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
using System.Text.Json;
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
    public ObservableCollection<DecodedString> DecodedStrings { get; } = [];
    public ObservableCollection<FileIndicator> FileIndicators { get; } = [];
    public ObservableCollection<StaticFinding> Findings { get; } = [];

    private string? _selectedPath;
    private string? _projectRoot;
    private bool _closeAnimationRunning;
    private bool _allowClose;
    private bool _isMapDragging;
    private Point _mapDragStart;
    private double _mapDragHorizontalOffset;
    private double _mapDragVerticalOffset;
    private AnalysisRunResult? _latestAnalysis;
    private string? _latestAnalysisPath;
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
            Filter = "Java source and artifacts (*.java;*.class;*.jar;*.war;*.ear;*.apk)|*.java;*.class;*.jar;*.war;*.ear;*.apk|All files (*.*)|*.*",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) == true)
            SelectSample(dialog.FileName);
    }

    private void SelectSample(string path)
    {
        _selectedPath = path;
        _latestAnalysis = null;
        _latestAnalysisPath = null;
        SelectedFileText.Text = path;
        AnalyzeButton.IsEnabled = true;
        StatusText.Text = "Sample selected · analysis has not started";
        FileReportStatus.Text = "Analyze the selected sample to populate its details.";
        FileDetailName.Text = IoPath.GetFileName(path);
        FileDetailPath.Text = path;
        FileDetailType.Text = "Not analyzed";
        FileDetailSize.Text = "—";
        FileDetailEntropy.Text = "—";
        FileDetailMd5.Text = "—";
        FileDetailSha1.Text = "—";
        FileDetailHash.Text = "—";
        FullFileMd5.Text = "—";
        FullFileSha1.Text = "—";
        FullFileSha256.Text = "—";
        FullAssessmentFileText.Text = "Analyze a sample to build its static report.";
        FullAssessmentPathText.Text = path;
        FullPeSummaryText.Text = "Analyze a sample to inspect PE structure and imported APIs.";
        FullPeSectionsGrid.ItemsSource = null;
        FullPeImportsGrid.ItemsSource = null;
        FullIocCountText.Text = "0 INDICATORS";
        FullEvidenceCountText.Text = "0 EVIDENCE ITEMS";
        FilePackerVerdict.Text = "Not assessed";
        FilePackerConfidence.Text = "Analysis has not started";
        FilePackerEvidenceList.ItemsSource = null;
        FileJavaSummary.Text = "Analysis has not started";
        FileClassesGrid.ItemsSource = null;
        FileEntriesGrid.ItemsSource = null;
        FileRegionsGrid.ItemsSource = null;
        DecodedStrings.Clear();
        FileIndicators.Clear();
        FullAssessmentVerdictText.Text = "Not assessed";
        FullAssessmentSummaryText.Text = "Analyze a sample to generate its static assessment.";
        FullAssessmentScoreText.Text = "0 / 100";
        FullAssessmentProgressBar.Value = 0;
        FullAssessmentEvidenceGrid.ItemsSource = null;
        CodeMapCanvas.Children.Clear();
        CodeMapStatus.Text = "Analyze the selected sample to map class references.";
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        WorkspaceTabs.SelectedItem = AboutTab;
    }

    private async void WorkspaceTabs_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var fileDetailsSelected = FileDetailsTab.IsSelected;
        var fullAnalysisSelected = FullAnalysisTab.IsSelected;
        if (!IsLoaded || (!fileDetailsSelected && !fullAnalysisSelected))
            return;

        var selectedPath = _selectedPath;
        if (selectedPath is null || !File.Exists(selectedPath))
        {
            var dialog = new OpenFileDialog
            {
                Title = "Select a sample for static analysis",
                Filter = "Java source and artifacts (*.java;*.class;*.jar;*.war;*.ear;*.apk)|*.java;*.class;*.jar;*.war;*.ear;*.apk|All files (*.*)|*.*",
                CheckFileExists = true
            };
            if (dialog.ShowDialog(this) != true)
                return;

            SelectSample(dialog.FileName);
            selectedPath = dialog.FileName;
        }

        if (_latestAnalysis is not null
            && string.Equals(_latestAnalysisPath, selectedPath, StringComparison.OrdinalIgnoreCase))
            return;

        if (await AnalyzeSampleAsync(selectedPath) is not null)
            WorkspaceTabs.SelectedItem = fullAnalysisSelected ? FullAnalysisTab : FileDetailsTab;
    }

    private async void File_Click(object sender, RoutedEventArgs e)
    {
        OverflowPopup.IsOpen = false;
        if (_selectedPath is null || !File.Exists(_selectedPath))
        {
            var openDialog = new OpenFileDialog
            {
                Title = "Select a sample for static analysis",
                Filter = "Java source and artifacts (*.java;*.class;*.jar;*.war;*.ear;*.apk)|*.java;*.class;*.jar;*.war;*.ear;*.apk|All files (*.*)|*.*",
                CheckFileExists = true
            };
            if (openDialog.ShowDialog(this) != true)
                return;

            SelectSample(openDialog.FileName);
        }

        var selectedPath = _selectedPath;
        if (selectedPath is null)
            return;

        var report = _latestAnalysis is not null
            && string.Equals(_latestAnalysisPath, selectedPath, StringComparison.OrdinalIgnoreCase)
                ? _latestAnalysis
                : await AnalyzeSampleAsync(selectedPath);
        if (report is null)
            return;

        var saveDialog = new SaveFileDialog
        {
            Title = "Save complete analysis report",
            Filter = "JSON report (*.json)|*.json",
            DefaultExt = ".json",
            AddExtension = true,
            FileName = $"{IoPath.GetFileNameWithoutExtension(selectedPath)}-analysis.json",
            OverwritePrompt = true
        };
        if (saveDialog.ShowDialog(this) != true)
            return;

        var classTargets = report.Java?.ClassAnalysis.Select(item => new
        {
            className = item.Name,
            classFileMajorVersion = item.MajorVersion,
            classFileMinorVersion = item.MinorVersion,
            javaTarget = GetJavaTargetVersion(item.MajorVersion)
        }).ToList();
        var reportDocument = new
        {
            reportVersion = 1,
            generatedAtUtc = DateTimeOffset.UtcNow,
            samplePath = selectedPath,
            compiler = new
            {
                vendor = "Not encoded in standard Java class-file metadata",
                classTargets
            },
            nativeAnalysis = report.Native,
            javaAnalysis = report.Java,
            javaStringDecoding = report.DecodedStrings,
            extractedStrings = report.ExtractedStrings,
            fullFileAssessment = report.Assessment
        };

        try
        {
            var json = JsonSerializer.Serialize(reportDocument, new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                WriteIndented = true
            });
            await File.WriteAllTextAsync(saveDialog.FileName, json);
            StatusText.Text = $"Analysis report saved · {IoPath.GetFileName(saveDialog.FileName)}";
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, exception.Message, "Could not save analysis report", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string GetJavaTargetVersion(int majorVersion) => majorVersion switch
    {
        >= 49 => $"Java {majorVersion - 44}",
        >= 45 => $"Java 1.{majorVersion - 44}",
        _ => "Unknown"
    };

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
            Filter = "Java source and artifacts (*.java;*.class;*.jar;*.war;*.ear;*.apk)|*.java;*.class;*.jar;*.war;*.ear;*.apk|All files (*.*)|*.*",
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
        File.Exists(path) && !string.Equals(IoPath.GetExtension(path), ".dproj", StringComparison.OrdinalIgnoreCase);

    private async void Analyze_Click(object sender, RoutedEventArgs e)
    {
        var selectedPath = _selectedPath;
        if (selectedPath is null || !File.Exists(selectedPath))
            return;

        _latestAnalysis = null;
        _latestAnalysisPath = null;
        await AnalyzeSampleAsync(selectedPath);
    }

    private async Task<AnalysisRunResult?> AnalyzeSampleAsync(string selectedPath)
    {
        AnalyzeButton.IsEnabled = false;
        StatusText.Text = "Reading file bytes and analyzing archive structure…";
        AnalysisStateBadge.Text = "ANALYZING";
        try
        {
            var report = await _analysisEngine.AnalyzeAsync(selectedPath);
            _latestAnalysis = report;
            _latestAnalysisPath = selectedPath;
            RenderReport(report.Native, report.Java, report.DecodedStrings, report.Assessment, report.ExtractedStrings);
            StatusText.Text = $"Analysis complete · {IoPath.GetFileName(selectedPath)} · sample was not executed";
            AnalysisStateBadge.Text = "STATIC ANALYSIS COMPLETE";
            WorkspaceTabs.SelectedIndex = 0;
            return report;
        }
        catch (Exception exception)
        {
            _latestAnalysis = null;
            _latestAnalysisPath = null;
            StatusText.Text = "Analysis failed · see details";
            AnalysisStateBadge.Text = "ANALYSIS ERROR";
            MessageBox.Show(this, exception.Message, "DeJavaEx analysis error", MessageBoxButton.OK, MessageBoxImage.Error);
            return null;
        }
        finally
        {
            AnalyzeButton.IsEnabled = _selectedPath is not null;
        }
    }

    private void RenderReport(NativeReport native, JavaReport? java, IReadOnlyList<DecodedString> decodedStrings,
        FullFileAssessment assessment, IReadOnlyList<ExtractedString> extractedStrings)
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

        FileReportStatus.Text = $"Static analysis details for {native.FileName} · sample was not executed.";
        FileDetailName.Text = native.FileName;
        FileDetailPath.Text = _latestAnalysisPath ?? native.FilePath;
        FileDetailType.Text = native.FileType;
        FileDetailSize.Text = FormatSize(native.SizeBytes);
        FileDetailEntropy.Text = $"{native.Entropy:F3} bits/byte";
        FileDetailMd5.Text = native.Md5;
        FileDetailSha1.Text = native.Sha1;
        FileDetailHash.Text = native.Sha256;
        FullAssessmentFileText.Text = $"{native.FileName} · {native.FileType} · {FormatSize(native.SizeBytes)} · entropy {native.Entropy:F3} bits/byte";
        FullAssessmentPathText.Text = native.FilePath;
        if (native.PeAnalysis is { } pe)
        {
            var timestamp = pe.Timestamp == 0
                ? "unknown timestamp"
                : DateTimeOffset.FromUnixTimeSeconds(pe.Timestamp).ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
            FullPeSummaryText.Text = $"{pe.Architecture} · {pe.Subsystem} · {(pe.IsDll ? "DLL" : "executable")} · "
                + $"entry point 0x{pe.EntryPointRva:X8} · base 0x{pe.ImageBase:X} · {timestamp} · "
                + $"{pe.SectionCount} sections · {pe.Imports.Count:N0} imported symbols · "
                + (pe.HasOverlay ? $"overlay {FormatSize((long)pe.OverlayBytes)}" : "no overlay detected");
            FullPeSectionsGrid.ItemsSource = pe.Sections;
            FullPeImportsGrid.ItemsSource = pe.Imports;
        }
        else
        {
            FullPeSummaryText.Text = "No valid PE headers found. Generic file hashes, strings, entropy and IOC scans still apply.";
            FullPeSectionsGrid.ItemsSource = Array.Empty<PeSection>();
            FullPeImportsGrid.ItemsSource = Array.Empty<PeImport>();
        }
        FullFileMd5.Text = native.Md5;
        FullFileSha1.Text = native.Sha1;
        FullFileSha256.Text = native.Sha256;
        FilePackerVerdict.Text = hasJavaPackerSignals ? "Bytecode marker" : native.Packer?.Verdict ?? "Not assessed";
        FilePackerConfidence.Text = hasJavaPackerSignals
            ? $"{javaPackerSignals.Count} Java constant-pool signals"
            : native.Packer?.Confidence ?? "No evidence returned";
        FilePackerEvidenceList.ItemsSource = packerEvidence.Count > 0
            ? packerEvidence.Select(text => new SignalView(text, (Brush)FindResource(hasJavaPackerSignals || native.Packer?.Level == "high" ? "Coral" : "Amber"))).ToList()
            : [new SignalView("No known packer signature was identified.", (Brush)FindResource("Mint"))];
        FileJavaSummary.Text = java is null
            ? "Java analysis was unavailable."
            : $"Status: {java.Status} · {java.ClassAnalysis.Count:N0} classes · {java.ClassAnalysis.Sum(item => item.MethodCount):N0} methods · {java.ClassAnalysis.Sum(item => item.FieldCount):N0} fields · {java.Calls.Count:N0} bytecode references · {java.ClassAnalysis.Sum(item => item.DynamicCallCount):N0} dynamic sites.";
        FileClassesGrid.ItemsSource = java?.ClassAnalysis.Select(item => new JavaClassDetail(
            item.Name,
            $"{item.MajorVersion}.{item.MinorVersion}",
            GetJavaTargetVersion(item.MajorVersion),
            item.MethodCount,
            item.FieldCount,
            item.CallCount,
            item.DynamicCallCount)).ToList() ?? [];
        FileEntriesGrid.ItemsSource = native.Entries;
        FileRegionsGrid.ItemsSource = native.Regions;
        DecodedStrings.Clear();
        foreach (var item in decodedStrings)
            DecodedStrings.Add(item);
        FileIndicators.Clear();
        foreach (var indicator in assessment.Indicators)
            FileIndicators.Add(indicator);
        FullIocCountText.Text = $"{assessment.Indicators.Count:N0} INDICATORS";
        FullEvidenceCountText.Text = $"{assessment.Evidence.Count:N0} EVIDENCE ITEMS";
        FullAssessmentVerdictText.Text = assessment.Verdict;
        FullAssessmentScoreText.Text = $"{assessment.Score} / 100";
        FullAssessmentSummaryText.Text = assessment.Summary;
        FullAssessmentScopeText.Text = assessment.Scope;
        FullAssessmentProgressBar.Value = assessment.Score;
        var assessmentBrush = assessment.Score switch
        {
            >= 60 => (Brush)FindResource("Coral"),
            >= 30 => (Brush)FindResource("Amber"),
            >= 12 => (Brush)FindResource("Amber"),
            _ => (Brush)FindResource("Mint")
        };
        FullAssessmentVerdictText.Foreground = assessmentBrush;
        FullAssessmentScoreText.Foreground = assessmentBrush;
        FullAssessmentProgressBar.Foreground = assessmentBrush;
        FullAssessmentEvidenceGrid.ItemsSource = assessment.Evidence;

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
        foreach (var value in extractedStrings)
            Strings.Add(value);
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
        DrawCodeMap(java);
    }

    private void DrawCodeMap(JavaReport? java)
    {
        CodeMapCanvas.Children.Clear();
        if (java is null)
        {
            CodeMapStatus.Text = "Java analysis is unavailable for this sample.";
            return;
        }

        var allClassNames = java.ClassAnalysis.Select(item => item.Name)
            .Distinct(StringComparer.Ordinal).OrderBy(name => name, StringComparer.Ordinal).ToList();
        if (allClassNames.Count == 0)
        {
            CodeMapStatus.Text = "No Java class references were found in this sample.";
            return;
        }

        const int maximumClasses = 48;
        const int maximumExternalNodes = 28;
        const double classStartX = 32;
        const double classStartY = 62;
        const double classStepX = 232;
        const double classStepY = 62;
        const double classWidth = 194;
        const double classHeight = 40;
        const double apiStartY = 62;
        const double apiStepY = 54;
        const double apiWidth = 310;

        var visibleClassNames = allClassNames.Take(maximumClasses).ToHashSet(StringComparer.Ordinal);
        var internalEdges = java.Calls
            .Where(call => visibleClassNames.Contains(call.ClassName) && visibleClassNames.Contains(call.Owner))
            .GroupBy(call => (call.ClassName, call.Owner))
            .Select(group => (Source: group.Key.ClassName, Target: group.Key.Owner, Count: group.Count()))
            .ToList();

        var outgoing = visibleClassNames.ToDictionary(name => name, _ => new SortedSet<string>(StringComparer.Ordinal), StringComparer.Ordinal);
        var indegree = visibleClassNames.ToDictionary(name => name, _ => 0, StringComparer.Ordinal);
        foreach (var edge in internalEdges)
        {
            if (outgoing[edge.Source].Add(edge.Target))
                indegree[edge.Target]++;
        }

        var layers = visibleClassNames.ToDictionary(name => name, _ => 0, StringComparer.Ordinal);
        var ready = new SortedSet<string>(indegree.Where(item => item.Value == 0).Select(item => item.Key), StringComparer.Ordinal);
        while (ready.Count > 0)
        {
            var current = ready.Min!;
            ready.Remove(current);
            foreach (var target in outgoing[current])
            {
                layers[target] = Math.Max(layers[target], layers[current] + 1);
                indegree[target]--;
                if (indegree[target] == 0)
                    ready.Add(target);
            }
        }

        var maxLayer = layers.Values.DefaultIfEmpty(0).Max();
        var positions = new Dictionary<string, Point>(StringComparer.Ordinal);
        for (var layer = 0; layer <= maxLayer; layer++)
        {
            var names = visibleClassNames.Where(name => layers[name] == layer).ToList();
            names = names.OrderBy(name =>
            {
                var parents = internalEdges.Where(edge => edge.Target == name && positions.ContainsKey(edge.Source))
                    .Select(edge => positions[edge.Source].Y).ToList();
                return parents.Count == 0 ? double.MaxValue : parents.Average();
            }).ThenBy(name => name, StringComparer.Ordinal).ToList();

            for (var index = 0; index < names.Count; index++)
                positions[names[index]] = new Point(classStartX + layer * classStepX, classStartY + index * classStepY);
        }

        var apiReferences = java.Calls
            .Where(call => visibleClassNames.Contains(call.ClassName)
                && !string.IsNullOrWhiteSpace(call.Owner)
                && !visibleClassNames.Contains(call.Owner)
                && !allClassNames.Contains(call.Owner, StringComparer.Ordinal))
            .Select(call => (Call: call, Target: call.Owner.StartsWith("bootstrap#", StringComparison.Ordinal)
                ? $"{call.Owner}.{call.Target}"
                : call.Owner))
            .GroupBy(item => (item.Call.ClassName, item.Target))
            .Select(group => (Source: group.Key.ClassName, Target: group.Key.Target, Count: group.Count()))
            .ToList();
        var visibleApiNames = apiReferences.GroupBy(edge => edge.Target)
            .OrderByDescending(group => group.Sum(edge => edge.Count))
            .ThenBy(group => group.Key, StringComparer.Ordinal)
            .Take(maximumExternalNodes)
            .Select(group => group.Key)
            .ToHashSet(StringComparer.Ordinal);
        var visibleApiReferences = apiReferences.Where(edge => visibleApiNames.Contains(edge.Target)).ToList();
        var apiStartX = classStartX + (maxLayer + 1) * classStepX;
        var orderedApiNames = visibleApiNames.OrderBy(name =>
        {
            var sources = visibleApiReferences.Where(edge => edge.Target == name).Select(edge => positions[edge.Source].Y).ToList();
            return sources.Count == 0 ? double.MaxValue : sources.Average();
        }).ThenBy(name => name, StringComparer.Ordinal).ToList();
        var maxLayerRows = Enumerable.Range(0, maxLayer + 1)
            .Select(layer => visibleClassNames.Count(name => layers[name] == layer)).DefaultIfEmpty(0).Max();
        var canvasHeight = Math.Max(560, Math.Max(maxLayerRows * classStepY, orderedApiNames.Count * apiStepY) + 150);
        CodeMapCanvas.Width = apiStartX + apiWidth + 32;
        CodeMapCanvas.Height = canvasHeight;

        var classHeading = new TextBlock
        {
            Text = "SAMPLE CLASSES  ·  REFERENCES FLOW RIGHT",
            FontSize = 9,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(145, 165, 161))
        };
        Canvas.SetLeft(classHeading, classStartX);
        Canvas.SetTop(classHeading, 18);
        CodeMapCanvas.Children.Add(classHeading);
        var apiHeading = new TextBlock
        {
            Text = "LIBRARIES / API TARGETS",
            FontSize = 9,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(223, 185, 112))
        };
        Canvas.SetLeft(apiHeading, apiStartX);
        Canvas.SetTop(apiHeading, 18);
        CodeMapCanvas.Children.Add(apiHeading);

        foreach (var (edge, edgeIndex) in internalEdges.Select((edge, index) => (edge, index)))
        {
            var source = positions[edge.Source];
            var target = positions[edge.Target];
            if (edge.Source == edge.Target)
            {
                AddMapConnection(
                    new Point(source.X + classWidth * 0.62, source.Y),
                    new Point(source.X + classWidth * 0.62, source.Y + classHeight),
                    new Point(source.X + classWidth + 42, source.Y - 12),
                    new Point(source.X + classWidth + 42, source.Y + classHeight + 12),
                    new SolidColorBrush(Color.FromRgb(115, 211, 168)), edge.Count,
                    $"{edge.Source} references itself · {edge.Count} link(s)", false);
                continue;
            }

            var sourceCenter = new Point(source.X + classWidth / 2, source.Y + classHeight / 2);
            var targetCenter = new Point(target.X + classWidth / 2, target.Y + classHeight / 2);
            var forward = target.X > source.X;
            var direction = forward ? 1d : -1d;
            var start = GetNodeBoundary(sourceCenter, targetCenter, classWidth / 2, classHeight / 2);
            var end = GetNodeBoundary(targetCenter, sourceCenter, classWidth / 2, classHeight / 2);
            var dx = end.X - start.X;
            var arcOffset = ((edgeIndex % 2 == 0) ? -1 : 1) * Math.Clamp(Math.Abs(targetCenter.Y - sourceCenter.Y) * 0.08, 18, 44);
            AddMapConnection(
                start,
                end,
                new Point(start.X + dx * 0.42, start.Y + arcOffset),
                new Point(end.X - dx * 0.42, end.Y + arcOffset),
                new SolidColorBrush(forward ? Color.FromRgb(127, 226, 177) : Color.FromRgb(227, 128, 109)), edge.Count,
                $"{edge.Source} references {edge.Target} · {edge.Count} link(s)", !forward);
        }

        var apiPositions = new Dictionary<string, Point>(StringComparer.Ordinal);
        for (var index = 0; index < orderedApiNames.Count; index++)
            apiPositions[orderedApiNames[index]] = new Point(apiStartX, apiStartY + index * apiStepY);

        foreach (var edge in visibleApiReferences)
        {
            var source = positions[edge.Source];
            var target = apiPositions[edge.Target];
            var sourceCenter = new Point(source.X + classWidth / 2, source.Y + classHeight / 2);
            var targetCenter = new Point(target.X + apiWidth / 2, target.Y + classHeight / 2);
            AddMapConnection(
                GetNodeBoundary(sourceCenter, targetCenter, classWidth / 2, classHeight / 2),
                GetNodeBoundary(targetCenter, sourceCenter, apiWidth / 2, classHeight / 2),
                null, null, new SolidColorBrush(Color.FromRgb(244, 195, 104)), edge.Count,
                $"{edge.Source} references {edge.Target} · {edge.Count} link(s)", true);
        }

        foreach (var entry in positions)
        {
            var node = new Border
            {
                Width = classWidth,
                Height = classHeight,
                Background = new SolidColorBrush(Color.FromRgb(25, 52, 43)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(75, 139, 111)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(7, 4, 7, 4),
                ToolTip = $"Class in sample\n{entry.Key}"
            };
            node.Child = new TextBlock
            {
                Text = entry.Key,
                FontSize = 10,
                Foreground = new SolidColorBrush(Color.FromRgb(220, 232, 228)),
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center
            };
            Canvas.SetLeft(node, entry.Value.X);
            Canvas.SetTop(node, entry.Value.Y);
            CodeMapCanvas.Children.Add(node);
        }

        foreach (var entry in apiPositions)
        {
            var node = new Border
            {
                Width = apiWidth,
                Height = classHeight,
                Background = new SolidColorBrush(Color.FromRgb(53, 44, 29)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(174, 135, 68)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(7, 4, 7, 4),
                ToolTip = $"External API or dynamic target\n{entry.Key}"
            };
            node.Child = new TextBlock
            {
                Text = entry.Key,
                FontSize = 10,
                Foreground = new SolidColorBrush(Color.FromRgb(231, 216, 188)),
                TextTrimming = TextTrimming.CharacterEllipsis,
                VerticalAlignment = VerticalAlignment.Center
            };
            Canvas.SetLeft(node, entry.Value.X);
            Canvas.SetTop(node, entry.Value.Y);
            CodeMapCanvas.Children.Add(node);
        }

        CodeMapStatus.Text = $"Showing {visibleClassNames.Count:N0} of {allClassNames.Count:N0} classes · "
            + $"{internalEdges.Count:N0} class links · {visibleApiNames.Count:N0} referenced API targets"
            + (visibleApiNames.Count < apiReferences.Select(edge => edge.Target).Distinct(StringComparer.Ordinal).Count()
                ? " · API targets limited to the most referenced"
                : "");
    }

    private void AddMapConnection(Point start, Point end, Point? firstControl, Point? secondControl,
        Brush stroke, int count, string description, bool dashed)
    {
        var dx = end.X - start.X;
        var dy = end.Y - start.Y;
        var bend = Math.Clamp(Math.Abs(dx) * 0.14, 24, 88);
        var first = firstControl ?? new Point(start.X + dx * 0.35, start.Y + Math.Sign(dy == 0 ? 1 : dy) * bend);
        var second = secondControl ?? new Point(end.X - dx * 0.35, end.Y - Math.Sign(dy == 0 ? 1 : dy) * bend);
        var figure = new PathFigure { StartPoint = start, IsFilled = false };
        figure.Segments.Add(new BezierSegment(first, second, end, true));
        var geometry = new PathGeometry();
        geometry.Figures.Add(figure);
        var thickness = Math.Clamp(1.6 + Math.Log2(count) * 0.45, 1.6, 3.4);
        var path = new System.Windows.Shapes.Path
        {
            Data = geometry,
            Stroke = stroke,
            StrokeThickness = thickness,
            Opacity = 0.9,
            StrokeDashArray = dashed ? [4, 3] : null,
            ToolTip = description
        };
        CodeMapCanvas.Children.Add(path);

        var tangent = end - second;
        if (tangent.Length < 0.1)
            tangent = end - start;
        tangent.Normalize();
        var normal = new Vector(-tangent.Y, tangent.X);
        var arrowBase = end - tangent * 10;
        var arrow = new Polygon
        {
            Points = new PointCollection
            {
                end,
                arrowBase + normal * 4.5,
                arrowBase - normal * 4.5
            },
            Fill = stroke,
            Opacity = 0.95,
            ToolTip = description
        };
        CodeMapCanvas.Children.Add(arrow);

        if (count > 1)
        {
            var label = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(13, 21, 22)),
                BorderBrush = stroke,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(7),
                Padding = new Thickness(4, 1, 4, 1),
                Child = new TextBlock { Text = count.ToString(), FontSize = 8, Foreground = stroke }
            };
            Canvas.SetLeft(label, (start.X + end.X) / 2 - 8);
            Canvas.SetTop(label, (start.Y + end.Y) / 2 - 8);
            CodeMapCanvas.Children.Add(label);
        }
    }

    private static Point GetNodeBoundary(Point center, Point toward, double halfWidth, double halfHeight)
    {
        var dx = toward.X - center.X;
        var dy = toward.Y - center.Y;
        if (Math.Abs(dx) < 0.001 && Math.Abs(dy) < 0.001)
            return center;
        var horizontalScale = Math.Abs(dx) < 0.001 ? double.PositiveInfinity : halfWidth / Math.Abs(dx);
        var verticalScale = Math.Abs(dy) < 0.001 ? double.PositiveInfinity : halfHeight / Math.Abs(dy);
        var scale = Math.Min(horizontalScale, verticalScale);
        return new Point(center.X + dx * scale, center.Y + dy * scale);
    }

    private void CodeMapScrollViewer_PreviewMouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        _isMapDragging = true;
        _mapDragStart = e.GetPosition(CodeMapScrollViewer);
        _mapDragHorizontalOffset = CodeMapScrollViewer.HorizontalOffset;
        _mapDragVerticalOffset = CodeMapScrollViewer.VerticalOffset;
        CodeMapScrollViewer.CaptureMouse();
        CodeMapScrollViewer.Cursor = System.Windows.Input.Cursors.SizeAll;
    }

    private void CodeMapScrollViewer_PreviewMouseLeftButtonUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (!_isMapDragging)
            return;
        _isMapDragging = false;
        CodeMapScrollViewer.ReleaseMouseCapture();
        CodeMapScrollViewer.Cursor = System.Windows.Input.Cursors.Hand;
    }

    private void CodeMapScrollViewer_PreviewMouseMove(object sender, System.Windows.Input.MouseEventArgs e)
    {
        if (!_isMapDragging || e.LeftButton != System.Windows.Input.MouseButtonState.Pressed)
            return;
        var current = e.GetPosition(CodeMapScrollViewer);
        CodeMapScrollViewer.ScrollToHorizontalOffset(_mapDragHorizontalOffset - (current.X - _mapDragStart.X));
        CodeMapScrollViewer.ScrollToVerticalOffset(_mapDragVerticalOffset - (current.Y - _mapDragStart.Y));
    }

    private void CodeMapScrollViewer_LostMouseCapture(object sender, System.Windows.Input.MouseEventArgs e)
    {
        _isMapDragging = false;
        CodeMapScrollViewer.Cursor = System.Windows.Input.Cursors.Hand;
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