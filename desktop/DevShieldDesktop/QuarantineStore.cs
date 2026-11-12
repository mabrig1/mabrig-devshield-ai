using System.Security.Cryptography;
using System.Text.Json;

namespace Mabrig.DevShieldDesktop;

// A reversible, manual action for positively identified ClamAV hits only.
// Never deletes infected files, alters system directories, or runs elevated.
internal sealed record QuarantineEntry(
    string Id, string OriginalPath, string Signature, string Sha256,
    DateTime QuarantinedUtc);

internal static class QuarantineStore
{
    private static string Root => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Mabrig", "DevShield", "Quarantine");

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private static bool HasReparseAncestor(string path)
    {
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            if (!File.Exists(current) && !Directory.Exists(current)) continue;
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                return true;
        }
        return false;
    }

    private static bool Under(string root, string file)
    {
        string prefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
        return file.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAllowed(string path, bool existing)
    {
        try
        {
            string absolute = Path.GetFullPath(path);
            if (!Path.IsPathFullyQualified(absolute)) return false;
            if (existing && !File.Exists(absolute)) return false;
            if (!existing && File.Exists(absolute)) return false;
            if (Directory.Exists(absolute)) return false;
            if (HasReparseAncestor(existing ? absolute : Path.GetDirectoryName(absolute)!)) return false;

            var roots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
            }.Where(Directory.Exists);

            if (!roots.Any(root => Under(root, absolute))) return false;
            // Renaming on the same drive is required. Never permit copy-and-delete across disks.
            if (!string.Equals(Path.GetPathRoot(absolute), Path.GetPathRoot(Root),
                StringComparison.OrdinalIgnoreCase)) return false;
            if (existing && (File.GetAttributes(absolute) &
                (FileAttributes.System | FileAttributes.ReparsePoint)) != 0) return false;
            return true;
        }
        catch { return false; }
    }

    internal static bool IsEligible(ClamDetection detection) =>
        IsAllowed(detection.FilePath, existing: true) &&
        ClamScanSafety.IsQuarantinableSignature(detection.Signature) &&
        detection.Sha256.Length == 64 &&
        detection.Sha256.All(Uri.IsHexDigit);

    private static string FileFor(string id) => Path.Combine(Root, id + ".quarantined");
    private static string RecordFor(string id) => Path.Combine(Root, id + ".json");

    private static string Hash(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    internal static QuarantineEntry Quarantine(ClamDetection detection)
    {
        if (!IsEligible(detection)) throw new InvalidOperationException(
            "Quarantine is limited to verified ClamAV detections in local Documents, Desktop, or Downloads.");
        string original = Path.GetFullPath(detection.FilePath);
        if (!Hash(original).Equals(detection.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("File content changed after scanning. Rescan first.");

        Directory.CreateDirectory(Root);
        if (HasReparseAncestor(Root)) throw new InvalidOperationException("Unsafe quarantine directory");
        string id = Guid.NewGuid().ToString("N");
        string destination = FileFor(id);
        string manifest = RecordFor(id);
        if (File.Exists(destination) || File.Exists(manifest))
            throw new InvalidOperationException("Quarantine collision");

        var record = new QuarantineEntry(id, original, detection.Signature,
            detection.Sha256, DateTime.UtcNow);
        // The marker file is made first, so a crash cannot produce an unrecorded moved file.
        using (var writer = new FileStream(manifest, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            JsonSerializer.Serialize(writer, record, JsonOptions);
        try
        {
            if (!IsAllowed(original, existing: true) ||
                !Hash(original).Equals(detection.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("File changed during quarantine preparation");
            File.Move(original, destination);
            return record;
        }
        catch
        {
            try { File.Delete(manifest); } catch { }
            throw;
        }
    }

    internal static IReadOnlyList<QuarantineEntry> List()
    {
        if (!Directory.Exists(Root) || HasReparseAncestor(Root))
            return [];
        var results = new List<QuarantineEntry>();
        foreach (var item in Directory.EnumerateFiles(Root, "*.json").Take(150))
        {
            try
            {
                if (HasReparseAncestor(item)) continue;
                var info = new FileInfo(item);
                if (info.Length > 16_384) continue;
                var entry = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(item));
                if (entry is null || !Guid.TryParseExact(entry.Id, "N", out _) ||
                    !Path.GetFileName(item).Equals(entry.Id + ".json", StringComparison.OrdinalIgnoreCase) ||
                    !File.Exists(FileFor(entry.Id))) continue;
                results.Add(entry);
            }
            catch { /* Skip damaged or untrusted entries. */ }
        }
        return results.OrderByDescending(r => r.QuarantinedUtc).ToArray();
    }

    internal static void Restore(QuarantineEntry entry)
    {
        if (!Guid.TryParseExact(entry.Id, "N", out _))
            throw new InvalidOperationException("Invalid quarantine record");
        string data = FileFor(entry.Id);
        string record = RecordFor(entry.Id);
        if (!File.Exists(data) || !File.Exists(record) ||
            HasReparseAncestor(data) || HasReparseAncestor(record))
            throw new InvalidOperationException("Quarantine item unavailable");
        // Re-read the on-disk record rather than accepting a caller-crafted entry.
        var stored = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(record));
        if (stored != entry) throw new InvalidOperationException("Quarantine record has changed");
        if (!IsAllowed(entry.OriginalPath, existing: false))
            throw new InvalidOperationException("Cannot restore to the recorded path");
        if (!Hash(data).Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Quarantined file hash changed; cannot restore");
        File.Move(data, entry.OriginalPath); // no overwrite; never runs the restored file.
        File.Delete(record);
    }

    // Smoke test runs only on an explicit --self-test-malware invocation.
    // It creates a harmless file in the caller's Downloads, then verifies reversible
    // same-drive quarantine/restore. It never touches existing user files.
    internal static bool SelfTest()
    {
        string downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        string name = ".devshield-benign-self-test-" + Guid.NewGuid().ToString("N") + ".txt";
        string file = Path.Combine(downloads, name);
        bool madeDownloads = !Directory.Exists(downloads);
        QuarantineEntry? saved = null;
        try
        {
            Directory.CreateDirectory(downloads);
            File.WriteAllText(file, "MABRIG DEVSHIELD BENIGN QUARANTINE TEST; NOT MALWARE");
            var fake = new ClamDetection(file, "DevShield.Benign.SelfTest", Hash(file));
            if (!IsEligible(fake)) return false;
            saved = Quarantine(fake);
            if (File.Exists(file) || !File.Exists(FileFor(saved.Id))) return false;
            Restore(saved);
            if (!File.Exists(file) || File.Exists(FileFor(saved.Id))) return false;
            return true;
        }
        catch { return false; }
        finally
        {
            // Preserve the quarantine if a restore failed; never delete an
            // isolated file merely because a test encountered an error.
            try { if (File.Exists(file)) File.Delete(file); } catch { }
            if (madeDownloads)
            {
                try { Directory.Delete(downloads, recursive: false); } catch { }
            }
        }
    }
}
