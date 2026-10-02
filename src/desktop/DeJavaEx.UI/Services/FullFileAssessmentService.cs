using System.IO;
using System.Net;
using System.Net.Sockets;
using System.IO.Compression;
using System.Text.RegularExpressions;
using DeJavaEx.UI.Models;

namespace DeJavaEx.UI.Services;

internal sealed class FullFileAssessmentService
{
    private static readonly Regex UrlPattern = new(@"\b(?:https?|ftp)://[^\s\""'<>]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex DomainPattern = new(@"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:COM|NET|ORG|INFO|BIZ|XYZ|TOP|IO|CO|ME|APP|DEV|CLOUD|SITE|ONLINE|RU|CN|UK|DE|FR|JP|AU)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Ipv4Pattern = new(@"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex RegistryPathPattern = new(@"(?i)\b(?:HKEY_(?:CURRENT_USER|LOCAL_MACHINE|USERS|CLASSES_ROOT|CURRENT_CONFIG)|HK(?:CU|LM|U|CR|CC))\\[^\s\""<>|,;]+", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex EmailPattern = new(@"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex FilePathPattern = new(@"(?i)(?:\b[A-Z]:\\(?:Users|ProgramData|Windows|Temp|AppData|Public)\\[^\s\""<>|]+|\\\\[^\s\""<>|]+|/tmp/[^\s\""<>|]+)", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex HashPattern = new(@"\b(?:[A-F0-9]{32}|[A-F0-9]{40}|[A-F0-9]{64})\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public FullFileAssessment Assess(string samplePath, NativeReport native, JavaReport? java, IReadOnlyList<DecodedString> decodedStrings)
    {
        var evidence = new List<StaticFinding>();
        var archiveStrings = ExtractArchiveStrings(samplePath);
        var indicators = FindIndicators(native, java, decodedStrings, archiveStrings);
        var score = 0;
        var categories = (java?.Indicators ?? []).Select(item => item.Category)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var analyzedText = GetAnalyzedText(native, java, decodedStrings, archiveStrings).ToList();

        foreach (var finding in java?.Indicators ?? [])
        {
            var points = finding.Category switch
            {
                "Process execution" => 24,
                "Native library loading" => 16,
                "Dynamic class loading" => 14,
                "Network access" => 12,
                "Reflection" => 8,
                "File system access" => 6,
                "Cryptography" => 3,
                "Dynamic invocation" => 2,
                _ => 2
            };
            score += points;
            evidence.Add(new StaticFinding(finding.Category, finding.Evidence, $"Java bytecode · +{points}"));
        }

        AddPeBehaviorEvidence(native.PeAnalysis, categories, evidence, ref score);
        AddTextBehaviorEvidence(analyzedText, categories, evidence, ref score);

        if (categories.Contains("Process execution") && categories.Contains("Network access"))
        {
            score += 20;
            evidence.Add(new StaticFinding("Combined behavior", "The same artifact references both process execution and network APIs.", "Heuristic correlation · +20"));
        }

        if (native.Packer?.Level == "high")
        {
            score += 10;
            evidence.Add(new StaticFinding("Packer marker", native.Packer.Verdict + ": " + native.Packer.Confidence, "C++ heuristics · +10"));
        }
        else if (native.Packer?.Level == "medium")
        {
            score += 5;
            evidence.Add(new StaticFinding("Possible packing", native.Packer.Confidence, "C++ heuristic · +5"));
        }

        if (java?.PackerSignals.Count > 0)
        {
            score += 8;
            evidence.Add(new StaticFinding("Java obfuscator marker", string.Join("; ", java.PackerSignals.Take(5)), "Java constant pool · +8"));
        }

        if (native.FileType == "Java class" && native.Entropy >= 7.5)
        {
            score += 4;
            evidence.Add(new StaticFinding("High class entropy", $"{native.Entropy:F3} bits per byte; this may indicate compression or obfuscation.", "C++ heuristic · +4"));
        }

        var urls = indicators.Count(item => item.Type == "URL");
        var ips = indicators.Count(item => item.Type == "IPv4");
        var registryPersistence = indicators.Count(item => item.Type == "Registry path" && IsPersistenceRegistryPath(item.Value));
        var iocPoints = Math.Min(6, urls * 2) + Math.Min(9, ips * 3) + Math.Min(12, registryPersistence * 6);
        if (iocPoints > 0)
        {
            score += iocPoints;
            evidence.Add(new StaticFinding("Indicators", $"Found {urls:N0} URL(s), {ips:N0} IPv4 address(es), and {registryPersistence:N0} persistence-related registry path(s).", $"String scan · +{iocPoints}"));
        }

        var decodedCount = decodedStrings.Select(item => item.Decoded).Distinct(StringComparer.Ordinal).Count();
        if (decodedCount > 0)
        {
            var points = Math.Min(6, decodedCount * 2);
            score += points;
            evidence.Add(new StaticFinding("Encoded text", $"Decoded {decodedCount:N0} readable string value(s); encoded text alone is not proof of malicious behavior.", $"Java/C++ string analysis · +{points}"));
        }

        foreach (var item in FindSuspiciousCommands(analyzedText))
        {
            score += 6;
            evidence.Add(new StaticFinding("Command or script indicator", item.Value, $"{item.Source} · +6"));
        }

        score = Math.Clamp(score, 0, 100);
        var verdict = score switch
        {
            >= 60 => "High risk · potentially malicious",
            >= 30 => "Suspicious · manual review recommended",
            >= 12 => "Some risk indicators · review recommended",
            _ => "No strong static indicators found"
        };
        var summary = score switch
        {
            >= 60 => "Several independent behavior indicators are present. Treat this file as high risk until reviewed.",
            >= 30 => "The file contains a combination of behaviors that merits analyst review.",
            >= 12 => "A small number of static indicators were found; inspect the evidence before making a decision.",
            _ => "The scan did not find strong known indicators. This does not prove the file is safe."
        };

        if (evidence.Count == 0)
            evidence.Add(new StaticFinding("Assessment scope", "No known high-risk bytecode behavior or packer marker was detected.", "Static analysis"));

        return new FullFileAssessment
        {
            Score = score,
            Verdict = verdict,
            Summary = summary,
            Scope = "Static heuristics only; no sample execution, live reputation lookup, or AV signature database. PE imports/sections, Java bytecode, extracted text, IOCs, and bounded ZIP contents are inspected. An endpoint is only a C2 candidate until validated.",
            Indicators = indicators,
            Evidence = evidence,
            ArchiveStrings = archiveStrings
        };
    }

    private static List<FileIndicator> FindIndicators(NativeReport native, JavaReport? java,
        IReadOnlyList<DecodedString> decodedStrings, IReadOnlyList<ExtractedString> archiveStrings)
    {
        var indicators = new List<FileIndicator>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var source in GetAnalyzedText(native, java, decodedStrings, archiveStrings))
        {
            foreach (Match match in UrlPattern.Matches(source.Value))
            {
                var value = match.Value.TrimEnd('.', ',', ';', ')', ']', '}');
                Add(indicators, seen, "URL", value, source.Source);
                if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && !IPAddress.TryParse(uri.Host, out _))
                    Add(indicators, seen, "Domain", uri.Host, source.Source);
            }

            foreach (Match match in Ipv4Pattern.Matches(source.Value))
            {
                if (IPAddress.TryParse(match.Value, out var address) && address.AddressFamily == AddressFamily.InterNetwork
                        && string.Equals(address.ToString(), match.Value, StringComparison.Ordinal))
                    Add(indicators, seen, "IPv4", match.Value, source.Source);
            }

            foreach (Match match in EmailPattern.Matches(source.Value))
                Add(indicators, seen, "Email", match.Value, source.Source);

            foreach (Match match in RegistryPathPattern.Matches(source.Value))
                Add(indicators, seen, "Registry path", match.Value.TrimEnd('.', ',', ';', ')', ']'), source.Source);

            foreach (Match match in DomainPattern.Matches(source.Value))
                Add(indicators, seen, "Domain", match.Value.TrimEnd('.'), source.Source);

            foreach (Match match in FilePathPattern.Matches(source.Value))
                Add(indicators, seen, "File path", match.Value.TrimEnd('.', ',', ';', ')', ']'), source.Source);

            foreach (Match match in HashPattern.Matches(source.Value))
                Add(indicators, seen, match.Length switch { 32 => "Embedded MD5", 40 => "Embedded SHA-1", _ => "Embedded SHA-256" }, match.Value, source.Source);
        }
        return indicators;
    }

    private static List<ExtractedString> FindSuspiciousCommands(IReadOnlyList<(string Value, string Source)> sources)
    {
        string[] markers = ["powershell -enc", "-encodedcommand", "rundll32", "regsvr32", "mshta.exe", "certutil -decode", "schtasks /create", "register-scheduledtask", "create-remotethread"];
        var results = new List<ExtractedString>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in sources)
        {
            if (!markers.Any(marker => source.Value.Contains(marker, StringComparison.OrdinalIgnoreCase)) || !seen.Add(source.Value))
                continue;
            results.Add(new ExtractedString(source.Value, source.Source));
            if (results.Count == 3)
                break;
        }
        return results;
    }

    private static IEnumerable<(string Value, string Source)> GetAnalyzedText(NativeReport native, JavaReport? java,
        IReadOnlyList<DecodedString> decodedStrings, IReadOnlyList<ExtractedString> archiveStrings) =>
        native.Strings.Select(value => (Value: value, Source: "C++ byte scan"))
            .Concat((java?.Strings ?? []).Select(value => (Value: value, Source: "Java constant pool")))
            .Concat(decodedStrings.Select(value => (Value: value.Decoded, Source: $"Decoded {value.Encoding}")))
            .Concat(archiveStrings.Select(value => (Value: value.Value, Source: value.Source)));

    private static void AddPeBehaviorEvidence(PeAnalysis? pe, HashSet<string> categories,
        List<StaticFinding> evidence, ref int score)
    {
        if (pe is null)
            return;

        var symbols = pe.Imports.Select(item => item.Symbol).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var rules = new (string Category, int Points, string[] Symbols)[]
        {
            ("Process execution", 18, ["CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW", "WinExec", "ShellExecuteA", "ShellExecuteW"]),
            ("Network access", 12, ["InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW", "HttpSendRequestA", "HttpSendRequestW", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "WSAStartup", "connect", "send", "getaddrinfo", "URLDownloadToFileA", "URLDownloadToFileW"]),
            ("Registry modification", 14, ["RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW", "RegDeleteValueA", "RegDeleteValueW", "RegDeleteKeyA", "RegDeleteKeyW"]),
            ("Service persistence", 16, ["OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW", "ChangeServiceConfigA", "ChangeServiceConfigW"]),
            ("Process injection capability", 20, ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtWriteVirtualMemory", "NtCreateThreadEx", "QueueUserAPC"]),
            ("Anti-debugging", 8, ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"]),
            ("Input capture capability", 12, ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"]),
            ("Cryptography", 4, ["CryptEncrypt", "BCryptEncrypt", "CryptAcquireContextA", "CryptAcquireContextW"])
        };

        foreach (var rule in rules)
        {
            var matches = rule.Symbols.Where(symbols.Contains).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (matches.Count == 0)
                continue;
            var alreadyObserved = !categories.Add(rule.Category);
            if (!alreadyObserved)
                score += rule.Points;
            evidence.Add(new StaticFinding(rule.Category, $"PE import table contains: {string.Join(", ", matches)}.",
                alreadyObserved ? "Native import corroborates Java bytecode (no extra score)" : $"Native import capability · +{rule.Points}"));
        }
    }

    private static void AddTextBehaviorEvidence(IReadOnlyList<(string Value, string Source)> sources,
        HashSet<string> categories, List<StaticFinding> evidence, ref int score)
    {
        var rules = new (string Category, int Points, string[] Markers)[]
        {
            ("Process execution", 16, ["Runtime.getRuntime().exec", "ProcessBuilder", "Start-Process", "Process.Start(", "os.system(", "subprocess.Popen", "CreateProcess", "WinExec", "ShellExecute"]),
            ("Network access", 10, ["Invoke-WebRequest", "DownloadString(", "DownloadFile(", "WebClient", "HttpClient", "WinHttpSendRequest", "InternetOpen", "URLDownloadToFile", "Socket("]),
            ("Registry modification", 12, ["RegSetValue", "RegCreateKey", "Set-ItemProperty", "New-ItemProperty", "Microsoft.Win32.Registry", "reg add "]),
            ("Service persistence", 14, ["CreateService", "New-Service", "sc.exe create", "Register-ScheduledTask", "schtasks /create"]),
            ("Process injection capability", 18, ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtWriteVirtualMemory", "NtCreateThreadEx", "QueueUserAPC"]),
            ("Anti-debugging", 7, ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"]),
            ("Office macro auto-execution", 12, ["AutoOpen", "Auto_Open", "Document_Open", "Workbook_Open", "Presentation_Open"]),
            ("PDF active-content marker", 8, ["/OpenAction", "/JavaScript", "/JS ", "/Launch", "/EmbeddedFile"]),
            ("Dynamic loader / shell configuration", 8, ["LD_PRELOAD", "/etc/cron", ".bashrc", "Runtime.getRuntime().load"])
        };

        foreach (var rule in rules)
        {
            string? matchedValue = null;
            var matchedSource = "";
            foreach (var source in sources)
            {
                if (!rule.Markers.Any(marker => source.Value.Contains(marker, StringComparison.OrdinalIgnoreCase)))
                    continue;
                matchedValue = source.Value;
                matchedSource = source.Source;
                break;
            }
            if (matchedValue is null)
                continue;

            var alreadyObserved = !categories.Add(rule.Category);
            if (!alreadyObserved)
                score += rule.Points;
            evidence.Add(new StaticFinding(rule.Category, matchedValue,
                alreadyObserved ? $"Text indicator corroborates another source ({matchedSource})" : $"Text heuristic · {matchedSource} · +{rule.Points}"));
        }
    }

    private static List<ExtractedString> ExtractArchiveStrings(string path)
    {
        const int maximumEntries = 10000;
        const int maximumEntryBytes = 2 * 1024 * 1024;
        const long maximumTotalBytes = 64L * 1024 * 1024;
        const int minimumStringLength = 5;
        var results = new List<ExtractedString>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        long totalBytes = 0;
        try
        {
            using var archive = ZipFile.OpenRead(path);
            foreach (var entry in archive.Entries.Take(maximumEntries))
            {
                if (entry.FullName.EndsWith('/') || entry.Length == 0
                        || entry.Length > maximumEntryBytes || totalBytes + entry.Length > maximumTotalBytes)
                    continue;
                try
                {
                    using var input = entry.Open();
                    using var output = new MemoryStream((int)entry.Length);
                    var buffer = new byte[8192];
                    int count;
                    while ((count = input.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        if (output.Length + count > maximumEntryBytes || totalBytes + output.Length + count > maximumTotalBytes)
                            break;
                        output.Write(buffer, 0, count);
                    }
                    var source = $"Archive entry: {entry.FullName}";
                    foreach (var value in ExtractPrintableStrings(output.GetBuffer(), (int)output.Length, minimumStringLength))
                        if (seen.Add(value))
                            results.Add(new ExtractedString(value, source));
                    totalBytes += output.Length;
                    if (totalBytes >= maximumTotalBytes)
                        break;
                }
                catch (InvalidDataException)
                {
                }
                catch (IOException)
                {
                }
            }
        }
        catch (InvalidDataException)
        {
        }
        catch (IOException)
        {
        }
        return results;
    }

    private static IEnumerable<string> ExtractPrintableStrings(byte[] bytes, int length, int minimumLength)
    {
        var found = new HashSet<string>(StringComparer.Ordinal);
        var current = new System.Text.StringBuilder();
        for (var index = 0; index < length; index++)
        {
            var value = bytes[index];
            if (value >= 0x20 && value <= 0x7e)
            {
                current.Append((char)value);
            }
            else
            {
                if (current.Length >= minimumLength)
                    found.Add(current.ToString());
                current.Clear();
            }
        }
        if (current.Length >= minimumLength)
            found.Add(current.ToString());

        for (var index = 0; index + 9 < length; index++)
        {
            current.Clear();
            var cursor = index;
            while (cursor + 1 < length && bytes[cursor] >= 0x20 && bytes[cursor] <= 0x7e && bytes[cursor + 1] == 0)
            {
                current.Append((char)bytes[cursor]);
                cursor += 2;
            }
            if (current.Length >= minimumLength)
            {
                found.Add(current.ToString());
                index = cursor - 1;
            }
        }
        return found;
    }

    private static bool IsPersistenceRegistryPath(string value) =>
        value.Contains("\\CurrentVersion\\Run", StringComparison.OrdinalIgnoreCase)
        || value.Contains("\\CurrentVersion\\RunOnce", StringComparison.OrdinalIgnoreCase)
        || value.Contains("\\Services\\", StringComparison.OrdinalIgnoreCase)
        || value.Contains("\\Winlogon", StringComparison.OrdinalIgnoreCase)
        || value.Contains("\\Image File Execution Options\\", StringComparison.OrdinalIgnoreCase)
        || value.Contains("\\AppInit_DLLs", StringComparison.OrdinalIgnoreCase);

    private static void Add(List<FileIndicator> indicators, HashSet<string> seen, string type, string value, string source)
    {
        if (string.IsNullOrWhiteSpace(value) || !seen.Add(type + "\0" + value))
            return;
        var context = type == "Registry path" && IsPersistenceRegistryPath(value)
            ? "Persistence-related registry location reference; a string alone does not prove it is written."
            : type is "URL" or "Domain" or "IPv4"
                ? "Network endpoint candidate; static extraction does not prove C2 use or malicious ownership."
                : "Extracted from static data; validate before blocking or attributing.";
        indicators.Add(new FileIndicator(type, value, source, context));
    }
}
