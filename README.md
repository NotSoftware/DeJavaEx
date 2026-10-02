# DeJavaEx

<p align="center">
	<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=24&pause=1200&color=76E4BC&center=true&vCenter=true&width=720&lines=Static+Java+Reverse+Engineering;Inspect+bytecode.+Understand+the+artifact.;No+sample+execution." alt="Static Java reverse engineering, without executing samples" />
</p>

<p align="center">
	<img alt="Windows" src="https://img.shields.io/badge/Platform-Windows%2010%2F11-3978B8?logo=windows&logoColor=white">
	<img alt="C Sharp and WPF" src="https://img.shields.io/badge/UI-C%23%20%2B%20WPF-512BD4?logo=dotnet&logoColor=white">
	<img alt="C++17" src="https://img.shields.io/badge/Engine-C%2B%2B17-00599C?logo=cplusplus&logoColor=white">
	<img alt="Java 11" src="https://img.shields.io/badge/Analyzer-Java%2011-ED8B00?logo=openjdk&logoColor=white">
	<img alt="Python utility" src="https://img.shields.io/badge/Utility-Python-3776AB?logo=python&logoColor=white">
</p>

**DeJavaEx is a Windows desktop workbench for static analysis of Java class files and archives.** It brings file inspection, bytecode references, archive browsing, findings, and CFR-powered source reconstruction into one focused dark interface.

> Samples are inspected as data. DeJavaEx does not execute or load the analyzed program.

## Why DeJavaEx

When reviewing an unfamiliar Java artifact, useful clues are often scattered across hashes, archive listings, bytecode tools, and decompilers. DeJavaEx puts those views together so you can quickly answer practical questions: What is this file? What is inside it? Which APIs does the bytecode reference? Is there a class worth examining more closely?

It is designed for triage, learning, and investigation. Results are evidence to guide further review, not a verdict about whether a file is malicious.

## Features

| Feature | What it shows | Why it helps |
| --- | --- | --- |
| File overview | File type and size, SHA-256, total and regional entropy | Identify and compare samples, and spot regions that may merit inspection |
| Archive map | Archive hierarchy, entry sizes, and compression information | Understand package contents without extracting files |
| Bytecode references | Method calls, field access, opcodes, signatures, and dynamic call sites | Trace static dependencies and focus review on notable behavior |
| Extracted strings | Printable byte strings and Java constant-pool text | Find embedded URLs, paths, messages, and other useful clues |
| Static findings | References to selected sensitive APIs, with evidence and source | Surface areas such as process execution, networking, reflection, crypto, and file access |
| Packer signals | Known tool markers and entropy-based clues | Flag possible obfuscation or packing for manual investigation |
| Decompiled source | Reconstructed Java-like source for a selected class, with syntax highlighting | Make bytecode easier to inspect; copy or save the reconstruction for follow-up |
| Project workspaces | Create or reopen `.dproj` projects and collect sample files | Keep related samples organized between analysis sessions |

## Interface

The app uses a dark, low-glare workspace with overview and detail tabs, a project explorer, and a syntax-highlighted source pane. Small hover and press transitions give buttons restrained feedback, while the class selector uses a slide-open dropdown. The interface uses lightweight text glyphs for navigation and status rather than an external icon pack.

## Supported Inputs

- Java `.class` files
- Java `.jar`, `.war`, and `.ear` archives
- Nested JAR entries inside supported archives
- Project files created by DeJavaEx (`.dproj`)

Archive browsing reads the archive index; it does not extract entries. The Java engine also recognizes ZIP-formatted archives, although the desktop workflow is centered on the Java extensions above.

## Quick Start

1. Launch the published `DeJavaEx.exe`.
2. Choose **Open sample**, or create a workspace with **Project Explorer > New project** and add files.
3. Select a sample and choose **Analyze file**.
4. Review **Overview**, **Bytecode refs**, **Archive map**, **Extracted strings**, and **Findings**.
5. To reconstruct a class, open **Decompiled source**, select a class, and choose **Decompile**. Copy or save the resulting source as needed.

## Requirements

To build from source on Windows 10/11 x64:

- .NET 10 SDK with the Windows Desktop targeting pack
- Visual Studio C++ x64 build tools
- JDK 11 or newer
- Internet access on the first build to download CFR 0.152, unless it is already available in `build/`
- PowerShell

The published desktop app is self-contained. The build still needs the toolchains above to compile its Java, C++, and .NET components.

## Build

From the repository root, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\build.ps1
```

The script compiles the Java analyzer and native engine, then publishes the desktop application to `build/publish/DeJavaEx.exe`. To create the requested delivery folder, copy the published executable to `DeJavaExApp/DeJavaEx.exe`. If the build output executable is currently running, the script uses a timestamped publish directory and prints its path.

## Troubleshooting

After cleaning generated folders, VS Code may temporarily underline AvalonEdit's XAML `TextEditor` as an unknown control because the `obj/` design-time assets were removed. This is an editor/project-reference warning, not a source-code error. Restore the project assets from the repository root:

```powershell
dotnet restore .\src\desktop\DeJavaEx.UI\DeJavaEx.UI.csproj
```

The restore recreates `obj/` locally; it is generated output and is ignored by Git. Reopen or reload the project in VS Code if the warning remains.

## Technologies

| Technology | Role |
| --- | --- |
| C# / WPF | Windows desktop interface and project workflow |
| C++17 | Native file, archive, entropy, and packer-signal analysis |
| Java 11 | Class-file and bytecode analysis engine |
| CFR 0.152 | Java-like source reconstruction |
| AvalonEdit | Read-only source editor with Java syntax highlighting |
| Python 3 | Optional standalone file metadata utility; not required by the desktop app |
| XAML / PowerShell / CMake | UI layout, build orchestration, and native build configuration |

An optional Python utility reports file type, size, MD5, SHA-1, SHA-256, and entropy:

```powershell
python src\tools\python\file_info.py path\to\sample.jar
```

Run its tests with:

```powershell
python -m unittest discover -s src\tools\python\tests -t . -v
```

## Safety and Analysis Limits

- DeJavaEx does not execute, load, or compile analyzed samples, and it does not extract archive entries.
- Packer detection is heuristic. High entropy can be caused by ordinary compression, and missing markers do not prove that a file is unpacked.
- API references are static indicators, not observed behavior. They may be incomplete or produce false positives.
- Decompiled output is reconstructed Java-like source. Original comments and exact source structure cannot be recovered reliably.
- The native ZIP index reader does not support ZIP64 archives.
- Java analysis skips individual class entries larger than 64 MiB.

Use the findings as investigative leads and validate important conclusions with additional analysis.

## Source Layout

```text
src/
	desktop/DeJavaEx.UI/  WPF app, views, models, and services
	engine/java/          Java bytecode analyzer
	engine/native/        C++ analysis engine
	tools/python/         Optional file metadata utility and tests
```

## Open Source

DeJavaEx is distributed under the [MIT License](LICENSE).

**Developer:** NotSoftware  
**GitHub:** [github.com/NotSoftware](https://github.com/NotSoftware)

**Discord:** NotSoftwaree
