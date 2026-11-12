using System.Diagnostics;
using System.Text.Json;

namespace Mabrig.DevShieldDesktop;

// Executes only a fixed, built-in read-only Windows PowerShell query on user request.
// The user supplies NO script text, process arguments, remote hosts or filenames.
// A missing/unavailable Defender cmdlet reports UNKNOWN, never "off" or "safe".
internal sealed record FirewallProfileStatus(string Name, bool? Enabled);
internal sealed record LaptopProtectionStatus(
    bool? AntivirusEnabled, bool? RealtimeProtectionEnabled,
    bool? AntimalwareServiceEnabled, string SignatureAge,
    IReadOnlyList<FirewallProfileStatus> FirewallProfiles,
    string Availability);

internal static class LaptopProtection
{
    // Fixed query uses only first-party Get-MpComputerStatus and Get-NetFirewallProfile.
    // Do not use a shell to build arbitrary commands, or fetch external scripts.
    private const string Query = "$ErrorActionPreference='Stop';" +
        "$a=$null;$f=@();" +
        "try{$a=Get-MpComputerStatus -ErrorAction Stop}catch{};" +
        "try{$f=@(Get-NetFirewallProfile -ErrorAction Stop|Select-Object Name,Enabled)}catch{};" +
        "[pscustomobject]@{" +
        "AntivirusEnabled=$a.AntivirusEnabled;" +
        "RealtimeProtectionEnabled=$a.RealTimeProtectionEnabled;" +
        "AntimalwareServiceEnabled=$a.AMServiceEnabled;" +
        "SignatureLastUpdated=$a.AntivirusSignatureLastUpdated;" +
        "Firewalls=@($f)" +
        "}|ConvertTo-Json -Compress -Depth 3";

    internal static bool? NullableBoolean(JsonElement json, string field)
    {
        if (!json.TryGetProperty(field, out var e)) return null;
        return e.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }

    internal static LaptopProtectionStatus Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var obj = document.RootElement;
        if (obj.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Invalid protection response");
        var firewall = new List<FirewallProfileStatus>();
        if (obj.TryGetProperty("Firewalls", out var profiles))
        {
            if (profiles.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in profiles.EnumerateArray().Take(8))
                    AddProfile(item);
            }
            else if (profiles.ValueKind == JsonValueKind.Object)
                AddProfile(profiles);
        }
        string age = "Unknown (live Defender metadata unavailable)";
        if (obj.TryGetProperty("SignatureLastUpdated", out var value) &&
            value.ValueKind == JsonValueKind.String &&
            DateTimeOffset.TryParse(value.GetString(), out var date))
        {
            var days = (DateTimeOffset.Now - date).TotalDays;
            age = days < 0 ? "Uncertain (clock discrepancy)" :
                days < 2 ? "Updated in past 48 hours (according to Windows)" :
                "Last Windows-reported update: " + date.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
        }

        var av = NullableBoolean(obj, "AntivirusEnabled");
        var rt = NullableBoolean(obj, "RealtimeProtectionEnabled");
        var service = NullableBoolean(obj, "AntimalwareServiceEnabled");
        return new(av, rt, service, age, firewall,
            av is null && firewall.Count == 0
                ? "Windows Security status unavailable; inspect Windows Security directly."
                : "Reported by local Windows APIs; may be absent under third-party antivirus or policy.");

        void AddProfile(JsonElement item)
        {
            if (item.ValueKind != JsonValueKind.Object) return;
            if (!item.TryGetProperty("Name", out var name) || name.ValueKind != JsonValueKind.String) return;
            string value = name.GetString() ?? "Unknown";
            if (value.Length is < 1 or > 40) return;
            firewall.Add(new FirewallProfileStatus(value, NullableBoolean(item, "Enabled")));
        }
    }

    internal static async Task<LaptopProtectionStatus> CheckAsync(CancellationToken cancellation)
    {
        var powershell = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powershell))
            return new(null, null, null, "Unknown", [],
                "Windows built-in PowerShell not available; check Windows Security manually.");

        using var process = new Process();
        process.StartInfo = new()
        {
            FileName = powershell,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var option in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", Query })
            process.StartInfo.ArgumentList.Add(option);

        try
        {
            if (!process.Start()) throw new InvalidOperationException("Query process did not start");
            using var reg = cancellation.Register(() =>
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                catch { /* Already exited. */ }
            });
            var output = process.StandardOutput.ReadToEndAsync(cancellation);
            var errors = process.StandardError.ReadToEndAsync(cancellation);
            await process.WaitForExitAsync(cancellation);
            string text = await output;
            _ = await errors; // Never surface potentially private OS diagnostics.
            if (text.Length is < 2 or > 32000 || process.ExitCode != 0)
                throw new InvalidDataException("Windows security status unavailable");
            return Parse(text);
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return new(null, null, null, "Unknown", [],
                "Unable to read Windows Security status. Check the Windows Security app directly.");
        }
    }

    internal static bool SelfTest()
    {
        const string sample = "{\"AntivirusEnabled\":true,\"RealtimeProtectionEnabled\":false," +
            "\"AntimalwareServiceEnabled\":true,\"SignatureLastUpdated\":null," +
            "\"Firewalls\":[{\"Name\":\"Public\",\"Enabled\":true},{\"Name\":\"Private\",\"Enabled\":false}]}";
        var s = Parse(sample);
        var unknown = Parse("{\"AntivirusEnabled\":null,\"Firewalls\":[]}");
        return s.AntivirusEnabled == true &&
            s.RealtimeProtectionEnabled == false &&
            s.AntimalwareServiceEnabled == true &&
            s.FirewallProfiles.Count == 2 &&
            s.FirewallProfiles[0].Enabled == true &&
            s.FirewallProfiles[1].Enabled == false &&
            unknown.AntivirusEnabled is null &&
            unknown.Availability.Contains("unavailable", StringComparison.OrdinalIgnoreCase);
    }
}
