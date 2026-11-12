using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Mabrig.DevShieldDesktop;

// Optional official ClamAV engine: never download or execute third-party installers.
// Call only explicitly chosen/installed clamscan.exe and freshclam.exe using argument arrays.
internal sealed record ClamDetection(string FilePath, string Signature, string Sha256);
internal sealed record ClamScanOutcome(bool Complete, IReadOnlyList<ClamDetection> Detections, string Status);
internal sealed record ClamUpdateOutcome(bool Success, string Status, DateTime? LatestDefinitionUtc);

internal static class ClamAvIntegration
{
    private static readonly Regex FoundLine =
        new(@"^(.+): ([A-Za-z0-9_.:+-]{1,180}) FOUND$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private const int MaxOutputChars = 4_000_000;

    internal static string? FindInstallFolder()
    {
        string[] bases = [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ClamAV"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ClamAV"),
            @"C:\ClamAV"
        ];
        return bases.FirstOrDefault(IsValidInstallFolder);
    }

    internal static bool IsValidInstallFolder(string folder)
    {
        try
        {
            string path = Path.GetFullPath(folder);
            if (!Directory.Exists(path)) return false;
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return false;
            return File.Exists(Path.Combine(path, "clamscan.exe")) &&
                   File.Exists(Path.Combine(path, "freshclam.exe")) &&
                   !IsReparse(Path.Combine(path, "clamscan.exe")) &&
                   !IsReparse(Path.Combine(path, "freshclam.exe"));
        }
        catch { return false; }
    }

    private static bool IsReparse(string path) =>
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;

    private static string DefinitionsDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Mabrig", "DevShield", "ClamAV-Definitions");

    internal static string? DefinitionsStatus()
    {
        string folder = DefinitionsDirectory;
        if (!Directory.Exists(folder)) return null;
        try
        {
            var files = new DirectoryInfo(folder).EnumerateFiles()
                .Where(f => (f.Extension.Equals(".cvd", StringComparison.OrdinalIgnoreCase) ||
                             f.Extension.Equals(".cld", StringComparison.OrdinalIgnoreCase)) &&
                             new[] { "main", "daily", "bytecode" }.Contains(Path.GetFileNameWithoutExtension(f.Name),
                               StringComparer.OrdinalIgnoreCase))
                .ToList();
            return files.Count == 0 ? null :
                $"ClamAV signatures installed; latest file: {files.Max(f => f.LastWriteTimeUtc):u}";
        }
        catch { return null; }
    }

    private static bool HasDefinitions() => DefinitionsStatus() is not null;

    private static string EnsureFreshClamConfig()
    {
        string database = DefinitionsDirectory;
        Directory.CreateDirectory(database);
        string config = Path.Combine(database, "freshclam.conf");
        if (!File.Exists(config))
        {
            if (database.Contains('"') || database.Contains('\n') || database.Contains('\r'))
                throw new InvalidOperationException("Unsupported definition directory");
            string data = "DatabaseDirectory \"" + database + "\"\n" +
                          "DatabaseMirror database.clamav.net\n" +
                          "Checks 2\n";
            using var writer = new FileStream(config, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            var bytes = Encoding.UTF8.GetBytes(data);
            writer.Write(bytes);
        }
        return config;
    }

    private static ProcessStartInfo MakeProcess(string exe, IEnumerable<string> args)
    {
        var info = new ProcessStartInfo
        {
            FileName = exe,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        return info;
    }

    private static async Task<(int Code, string Output, bool Truncated)> RunAsync(
        ProcessStartInfo info, CancellationToken token)
    {
        using var process = new Process { StartInfo = info };
        if (!process.Start()) throw new InvalidOperationException("Security engine failed to start");
        using var registration = token.Register(() =>
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch { /* Process may already have exited. */ }
        });
        var stdout = ReadCappedAsync(process.StandardOutput, token);
        var stderr = ReadCappedAsync(process.StandardError, token);
        await process.WaitForExitAsync(token);
        var a = await stdout;
        var b = await stderr;
        // Error output is never surfaced raw; it may contain local user paths.
        return (process.ExitCode, a.Text, a.Truncated || b.Truncated);
    }

    private static async Task<(string Text, bool Truncated)> ReadCappedAsync(
        StreamReader reader, CancellationToken token)
    {
        var buffer = new char[4096];
        var result = new StringBuilder();
        var over = false;
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), token)) > 0)
        {
            if (result.Length + count <= MaxOutputChars) result.Append(buffer, 0, count);
            else over = true;
        }
        return (result.ToString(), over);
    }

    internal static IReadOnlyList<(string File, string Signature)> ParseHits(string output)
    {
        var list = new List<(string File, string Signature)>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (list.Count >= 300) break;
            var found = FoundLine.Match(line.TrimEnd('\r'));
            if (found.Success && Path.IsPathFullyQualified(found.Groups[1].Value))
                list.Add((found.Groups[1].Value, found.Groups[2].Value));
        }
        return list;
    }

    internal static bool SelfTest() {
        var hits = ParseHits("C:\\Users\\Test\\Downloads\\fixture.txt: Win.Test.EICAR_HDB-1 FOUND\n");
        return hits.Count == 1 && hits[0].File.EndsWith("fixture.txt", StringComparison.Ordinal) &&
               hits[0].Signature == "Win.Test.EICAR_HDB-1" &&
               ParseHits("C:\\temp\\clean.txt: OK\n").Count == 0 &&
               ParseHits("run: Malware FOUND\n").Count == 0;
    }

    internal static async Task<ClamUpdateOutcome> UpdateDefinitionsAsync(
        string installFolder, CancellationToken token)
    {
        if (!IsValidInstallFolder(installFolder))
            return new(false, "ClamAV is not installed or selected.", null);
        try
        {
            string config = EnsureFreshClamConfig();
            var command = MakeProcess(Path.Combine(installFolder, "freshclam.exe"),
                ["--config-file=" + config]);
            var (code, output, truncated) = await RunAsync(command, token);
            if (code != 0 || truncated || !HasDefinitions())
                return new(false, "FreshClam could not complete an official signature update. Check its local configuration, connection, or vendor rate limit.", null);
            var info = new DirectoryInfo(DefinitionsDirectory)
                .EnumerateFiles().Where(f => f.Extension is ".cvd" or ".cld")
                .OrderByDescending(f => f.LastWriteTimeUtc).FirstOrDefault();
            return new(true, "Official ClamAV signatures are available. Updated via FreshClam.", info?.LastWriteTimeUtc);
        }
        catch (OperationCanceledException) { throw; }
        catch { return new(false, "ClamAV signature update failed. Review the local FreshClam configuration.", null); }
    }

    internal static async Task<ClamScanOutcome> ScanAsync(
        string installFolder, string target, CancellationToken token)
    {
        if (!IsValidInstallFolder(installFolder))
            return new(false, Array.Empty<ClamDetection>(), "Select an official ClamAV installation first.");
        if (!HasDefinitions())
            return new(false, Array.Empty<ClamDetection>(), "Virus definitions not installed. Select Update definitions first.");
        string absolute = Path.GetFullPath(target);
        if (!File.Exists(absolute) && !Directory.Exists(absolute))
            return new(false, Array.Empty<ClamDetection>(), "Selected path does not exist.");
        var args = new[]
        {
            "--database=" + DefinitionsDirectory,
            "--recursive", "--infected", "--no-summary",
            "--max-filesize=100M", "--max-scansize=250M", absolute
        };
        try
        {
            var (exit, output, overflow) = await RunAsync(
                MakeProcess(Path.Combine(installFolder, "clamscan.exe"), args), token);
            var listed = ParseHits(output);
            var hits = new List<ClamDetection>();
            bool incomplete = overflow || listed.Count >= 300 || exit is not (0 or 1) ||
                output.Contains("ERROR", StringComparison.OrdinalIgnoreCase);
            foreach (var item in listed)
            {
                try
                {
                    var real = Path.GetFullPath(item.File);
                    if (!File.Exists(real) || !IsWithinScanTarget(absolute, real) ||
                        IsReparse(real)) { incomplete = true; continue; }
                    using var stream = new FileStream(real, FileMode.Open, FileAccess.Read, FileShare.Read);
                    string hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, token));
                    hits.Add(new ClamDetection(real, item.Signature, hash));
                }
                catch { incomplete = true; }
            }
            if (exit == 1 && listed.Count == 0) incomplete = true;
            return new(!incomplete, hits,
                incomplete ? "Incomplete ClamAV scan: review file coverage and engine errors." :
                hits.Count > 0 ? "ClamAV identified malware signatures; review before quarantine." :
                "No ClamAV signatures detected in scanned content; this does not establish safety.");
        }
        catch (OperationCanceledException) { throw; }
        catch { return new(false, Array.Empty<ClamDetection>(), "ClamAV scan failed or database could not load."); }
    }

    private static bool IsWithinScanTarget(string target, string hit)
    {
        if (File.Exists(target)) return Path.GetFullPath(target)
            .Equals(hit, StringComparison.OrdinalIgnoreCase);
        string folder = Path.TrimEndingDirectorySeparator(Path.GetFullPath(target)) +
                        Path.DirectorySeparatorChar;
        return hit.StartsWith(folder, StringComparison.OrdinalIgnoreCase);
    }
}
