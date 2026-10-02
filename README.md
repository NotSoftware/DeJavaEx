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

**DeJavaEx is a Windows desktop workbench for multi-format static file triage, with deeper structural analysis for Java and Windows PE files.** It combines hashes, readable strings, IOCs, PE imports, Java bytecode references, archive browsing, and CFR-powered source reconstruction.

> Samples are inspected as data. DeJavaEx does not execute or load the analyzed program.


# DeJavaEx OverFlow 

<img width="1920" height="1032" alt="Screenshot 2026-10-02 145049" src="https://github.com/user-attachments/assets/867b873e-1e8a-40cc-b895-7f59d7608d10" />


## Why DeJavaEx

When reviewing an unfamiliar Java artifact, useful clues are often scattered across hashes, archive listings, bytecode tools, and decompilers. DeJavaEx puts those views together so you can quickly answer practical questions: What is this file? What is inside it? Which APIs does the bytecode reference? Is there a class worth examining more closely?

It is designed for triage, learning, and investigation. Results are evidence to guide further review, not a verdict about whether a file is malicious.

## Recent Updates

- Added **Full Analysis** with MD5, SHA-1, SHA-256, strings, decoded text, IOCs, evidence, and an explainable heuristic risk score.
- Added PE architecture, sections, entropy, overlay size, and imported APIs; imports describe capabilities, not proof that APIs ran.
- Added URL, domain, IPv4, registry path, file path, email, and embedded-hash indicators, plus static clues for execution, networking, persistence, injection, and anti-analysis.
- Added signature recognition for PE, ELF, Mach-O, DEX, PDF, Office, RTF, SQLite, images, and common archives.
- Added APK class scanning and bounded in-memory scanning of ZIP-based entry contents.
- Reworked the **Map** tab into a layered, pannable class/API graph with directional links.
- Moved Base64, hexadecimal, URL-percent, and Java Unicode escape decoding into the Java engine.

## Features

| Feature | What it shows | Why it helps |
| --- | --- | --- |
| File overview | File type and size, SHA-256, total and regional entropy | Identify and compare samples, and spot regions that may merit inspection |
| Full file assessment | MD5, SHA-1, SHA-256, PE structure/imports, Java bytecode evidence, bounded archive strings, decoded text, extracted IOCs, and an explainable risk score | Collect triage evidence in one report without executing the sample |
| Archive map | Archive hierarchy, entry sizes, and compression information | Understand package contents without extracting files |
| Bytecode references | Method calls, field access, opcodes, signatures, and dynamic call sites | Trace static dependencies and focus review on notable behavior |
| Extracted strings | Printable byte strings and Java constant-pool text | Find embedded URLs, paths, messages, and other useful clues |
| Static findings | References to selected sensitive APIs, with evidence and source | Surface areas such as process execution, networking, reflection, crypto, and file access |
| Packer signals | Known tool markers and entropy-based clues | Flag possible obfuscation or packing for manual investigation |
| Multi-format triage | File signatures, hashes, entropy, strings, and IOCs | Inspect non-Java files without treating a string match as proof of behavior |
| Decompiled source | Reconstructed Java-like source for a selected class, with syntax highlighting | Make bytecode easier to inspect; copy or save the reconstruction for follow-up |
| Project workspaces | Create or reopen `.dproj` projects and collect sample files | Keep related samples organized between analysis sessions |

## Interface

The app uses a dark, low-glare workspace with Overview, Full Analysis, File details, and a pannable Map tab, alongside a project explorer and syntax-highlighted source pane. The Map tab lays out sample classes and referenced APIs with directional links.

## Supported Inputs

- Any file can be submitted for file identification, MD5/SHA hashes, entropy, readable-string, and IOC triage.
- Java `.class` files
- Java `.jar`, `.war`, `.ear`, and Android `.apk` archives
- Windows PE executables and libraries receive header, section, entropy, overlay, and import-table analysis.
- ELF, Mach-O, DEX, PDF, Office, RTF, SQLite, images, scripts, and other formats receive signature identification and generic string/IOC triage.
- ZIP-based archives, including nested JAR entries and Office Open XML packages
- Project files created by DeJavaEx (`.dproj`)

Archive browsing reads the archive index. Full Analysis may read bounded ZIP entry contents in memory for string and IOC scanning; it does not write extracted files to disk. Java bytecode analysis also scans classes inside APK archives.

## Quick Start

1. Launch the published `DeJavaEx.exe`.
2. Choose **Open sample**, or create a workspace with **Project Explorer > New project** and add files.
3. Select a sample and choose **Analyze file**.
4. Review **Overview**, **Full Analysis**, **Map**, **Bytecode refs**, **Archive map**, **Extracted strings**, and **Findings**.
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
| C++17 | Native hashing, format signatures, archive index, entropy, strings, and PE import/section parsing |
| Java 11 | Class-file and bytecode analysis engine |
| C# assessment service | IOC extraction and explainable risk aggregation across native and Java evidence |
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

- DeJavaEx does not execute, load, or compile analyzed samples. ZIP entries may be decompressed in memory for bounded string/IOC inspection, but are never written to disk.
- Archive string inspection is limited to 10,000 entries, 2 MiB per entry, and 64 MiB total expanded data. The native reader limits input files to 1 GiB.
- Packer detection is heuristic. High entropy can be caused by ordinary compression, and missing markers do not prove that a file is unpacked.
- API references are static indicators, not observed behavior. They may be incomplete or produce false positives.
- PE imports, registry strings, script commands, and Java API references indicate possible capabilities; they do not prove those actions ran. A network endpoint is an IOC candidate, not a confirmed C2.
- The full-file risk score is explainable static triage, not an antivirus verdict or a live reputation lookup. A low score does not prove a file is safe.
- Decompiled output is reconstructed Java-like source. Original comments and exact source structure cannot be recovered reliably.
- The native archive tree reader does not support ZIP64; the bounded content scan uses the .NET ZIP reader.
- Java analysis skips classes over 64 MiB and stops after scanning 100,000 classes; nested JAR entries have a 256 MiB size limit.
- PE import/section analysis currently applies to Windows PE. ELF and Mach-O receive generic static triage rather than dependency-table parsing.

Use the findings as investigative leads and validate important conclusions with additional analysis.

## Source Layout

```text
src/
	desktop/DeJavaEx.UI/  WPF app, views, models, and analysis services
	engine/java/          Java bytecode analyzer
	engine/native/        C++ file, archive, and PE analysis engine
	tools/python/         Optional file metadata utility and tests
```

## Open Source

DeJavaEx is distributed under the [MIT License](LICENSE).

**Developer:** NotSoftware  
**GitHub:** [github.com/NotSoftware](https://github.com/NotSoftware)

---

# Thank
Thank you to everyone who has used the DeJavaEx tool; developing it was quite a challenge. I hope it gives security researchers an edge when analyzing Java-based malware. If you have any questions about the tool, please reach out to me on Discord (Username: NotSoftwaree), and I will get back to you as soon as possible

