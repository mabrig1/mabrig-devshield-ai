using System.Globalization;
using System.Text.RegularExpressions;

namespace Mabrig.DevShieldDesktop;

// Strict, side-effect-free safety checks around optional ClamAV integration.
// A zero-detection verdict is only meaningful when the selected files were eligible
// and the engine emitted a coherent scan summary without warnings/errors/limits.
internal sealed record ClamTargetCoverage(bool Eligible, int Files, long Bytes, string Reason);
internal sealed record ClamEngineSummary(bool Valid, int ScannedFiles, int InfectedFiles, int Errors);

internal static class ClamScanSafety
{
    private const int MaxPaths = 2500;
    private const int MaxDepth = 30;
    private const long MaxSingleFileBytes = 100L * 1024 * 1024;
    private const long MaxTotalBytes = 1024L * 1024 * 1024;

    private static readonly Regex SummaryField = new(
        @"^\s*(Scanned files|Infected files|Total errors):\s*([0-9]+)\s*$",
        RegexOptions.Multiline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    internal static ClamEngineSummary ParseSummary(string output)
    {
        int? scanned = null, infected = null, errors = null;
        foreach (Match match in SummaryField.Matches(output.Replace("\r\n", "\n")))
        {
            if (!int.TryParse(match.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var n))
                return new(false, 0, 0, 0);
            switch (match.Groups[1].Value.ToLowerInvariant())
            {
                case "scanned files": scanned = n; break;
                case "infected files": infected = n; break;
                case "total errors": errors = n; break;
            }
        }
        // Some ClamAV versions omit Total errors when zero.
        if (scanned is null || infected is null || infected > scanned)
            return new(false, scanned ?? 0, infected ?? 0, errors ?? 0);
        return new(true, scanned.Value, infected.Value, errors ?? 0);
    }

    internal static bool HasUntrustedCoverageSignal(string stdout, string stderr, bool truncated)
    {
        if (truncated) return true;
        // Includes "Heuristics.Limits.Exceeded FOUND" as non-malware coverage warning,
        // and other ClamAV file-read/parsing/timeout messages. Never quote raw paths.
        string combined = stdout + "\n" + stderr;
        return Regex.IsMatch(combined,
            @"\b(?:ERROR|WARNING|SKIPPED|SCAN\s+ABORTED|SCAN\s+TIMEOUT|LIMIT\s+EXCEEDED|Heuristics\.Limits\.Exceeded)\b",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    internal static bool IsQuarantinableSignature(string signature) =>
        !string.IsNullOrWhiteSpace(signature) &&
        signature.Length <= 180 &&
        !signature.StartsWith("Heuristics.", StringComparison.OrdinalIgnoreCase) &&
        !signature.StartsWith("PUA.", StringComparison.OrdinalIgnoreCase) &&
        !signature.StartsWith("Test.", StringComparison.OrdinalIgnoreCase) &&
        !signature.StartsWith("Eicar.", StringComparison.OrdinalIgnoreCase) &&
        !signature.Contains("EICAR", StringComparison.OrdinalIgnoreCase);

    internal static bool IsCoverageHeuristic(string signature) =>
        signature.StartsWith("Heuristics.", StringComparison.OrdinalIgnoreCase);

    internal static ClamTargetCoverage InspectTarget(string input)
    {
        try
        {
            string root = Path.GetFullPath(input);
            FileAttributes attrs = File.GetAttributes(root);
            if ((attrs & FileAttributes.ReparsePoint) != 0)
                return new(false, 0, 0, "Reparse point or symlink target is not eligible.");
            int seen = 0;
            int files = 0;
            long total = 0;
            var dirs = new Stack<(string Directory, int Depth)>();
            if ((attrs & FileAttributes.Directory) != 0)
                dirs.Push((root, 0));
            else
                InspectFile(root);

            while (dirs.Count > 0)
            {
                var (dir, depth) = dirs.Pop();
                if (depth > MaxDepth)
                    return new(false, files, total, "Folder nesting exceeds bounded scan depth.");
                foreach (var item in Directory.EnumerateFileSystemEntries(dir))
                {
                    var attributes = File.GetAttributes(item);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                        return new(false, files, total, "Scan target contains a symlink or junction.");
                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        if (seen++ >= MaxPaths)
                            return new(false, files, total, "Scan target exceeds file/directory count limit.");
                        dirs.Push((item, depth + 1));
                    }
                    else InspectFile(item);
                }
            }
            return new(true, files, total, "Target files are within configured scanner limits.");

            void InspectFile(string file)
            {
                var f = new FileInfo(file);
                if (!f.Exists) throw new IOException("File unavailable");
                if ((f.Attributes & (FileAttributes.ReparsePoint | FileAttributes.Offline)) != 0)
                    throw new IOException("Unsupported file type");
                if (f.Length > MaxSingleFileBytes)
                    throw new IOException("File exceeds scanner's 100 MiB cap");
                if (++seen > MaxPaths || f.Length + total > MaxTotalBytes)
                    throw new IOException("Aggregate scan size or file count cap exceeded");
                files++;
                total += f.Length;
            }
        }
        catch
        {
            return new(false, 0, 0,
                "Target is inaccessible, exceeds scanner caps, or contains unsupported file entries.");
        }
    }

    internal static bool IsSuccessfulCoverage(int exitCode, string stdout, string stderr,
        bool truncated, ClamTargetCoverage target, int matchedCount)
    {
        if (!target.Eligible || exitCode is not (0 or 1) || HasUntrustedCoverageSignal(stdout, stderr, truncated))
            return false;
        var summary = ParseSummary(stdout);
        if (!summary.Valid || summary.Errors > 0 || summary.ScannedFiles < target.Files ||
            summary.InfectedFiles < matchedCount || (exitCode == 1 && matchedCount == 0))
            return false;
        return true;
    }

    internal static bool SelfTest()
    {
        const string clean = "----------- SCAN SUMMARY -----------\nScanned files: 2\nInfected files: 0\nTime: 0.010 sec\n";
        const string infected = "C:\\Users\\fixture.txt: Win.Test.Demo-1 FOUND\n" +
            "----------- SCAN SUMMARY -----------\nScanned files: 1\nInfected files: 1\n";
        var normal = new ClamTargetCoverage(true, 2, 100, "ok");
        return IsSuccessfulCoverage(0, clean, "", false, normal, 0) &&
            !IsSuccessfulCoverage(0, clean, "", false, new(true, 3, 100, "unscanned file"), 0) &&
            !IsSuccessfulCoverage(0, clean, "WARNING: file skipped", false, normal, 0) &&
            !IsSuccessfulCoverage(0, clean, "", true, normal, 0) &&
            !IsSuccessfulCoverage(0, "random output", "", false, normal, 0) &&
            IsSuccessfulCoverage(1, infected, "", false, new(true, 1, 10, "ok"), 1) &&
            !IsSuccessfulCoverage(1, infected, "", false, new(true, 1, 10, "ok"), 0) &&
            !IsQuarantinableSignature("Heuristics.Limits.Exceeded") &&
            !IsQuarantinableSignature("PUA.Win.Adware") &&
            IsQuarantinableSignature("Win.Trojan.Demo-1") &&
            !IsQuarantinableSignature("Eicar-Test-Signature") &&
            !IsSuccessfulCoverage(0, clean, "", false, new(false, 2, 0, "oversized"), 0);
    }
}
