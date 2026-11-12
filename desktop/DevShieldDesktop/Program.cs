using System.Diagnostics;
using System.Drawing;
using System.Text.Json;
using System.Windows.Forms;

namespace Mabrig.DevShieldDesktop;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--version")
        {
            Console.WriteLine("DevShield Desktop 0.1.0 — unsigned experimental build");
            return;
        }

        if (args.Length == 1 && args[0] == "--self-test-malware")
        {
            Environment.ExitCode = ClamAvIntegration.SelfTest() ? 0 : 1;
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new ScannerForm());
    }
}

internal sealed partial class ScannerForm : Form
{
    private readonly TextBox _selectedPath = new();
    private readonly Label _status = new();
    private readonly ListView _findings = new();
    private readonly ProgressBar _progress = new();
    private readonly Button _chooseFile;
    private readonly Button _chooseFolder;
    private readonly Button _downloads;
    private readonly Button _scan;
    private readonly Button _cancel;
    private readonly Button _export;
    private readonly Button _watch;
    private readonly System.Windows.Forms.Timer _watchTimer = new() { Interval = 60_000 };
    private CancellationTokenSource? _scanCancellation;
    private string? _lastReport;
    private bool _running;

    private static readonly Color Navy = Color.FromArgb(14, 28, 49);
    private static readonly Color Blue = Color.FromArgb(24, 94, 201);
    private static readonly Color Subtle = Color.FromArgb(245, 248, 251);

    internal ScannerForm()
    {
        Text = "DevShield Endpoint Threat Guard — MABRIG Technologies";
        Width = 1100;
        Height = 750;
        MinimumSize = new Size(850, 570);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.White;
        Font = new Font("Segoe UI", 9F);
        FormBorderStyle = FormBorderStyle.Sizable;
        ShowIcon = false;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 6,
            Padding = new Padding(20, 16, 20, 12),
            BackColor = Color.White
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 88));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 65));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 152));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        Controls.Add(root);

        var top = new Panel { Dock = DockStyle.Fill };
        top.Controls.Add(new Label
        {
            Text = "DEVSHIELD  /  ENDPOINT THREAT GUARD",
            Font = new Font("Segoe UI", 18F, FontStyle.Bold),
            ForeColor = Navy, Dock = DockStyle.Top, Height = 43
        });
        top.Controls.Add(new Label
        {
            Text = "Offline developer security checks — local files only, no uploads or cloud account required",
            ForeColor = Color.DimGray, Dock = DockStyle.Bottom, Height = 30
        });
        root.Controls.Add(top, 0, 0);

        root.Controls.Add(new Label
        {
            Dock = DockStyle.Fill,
            BackColor = Color.FromArgb(255, 247, 229),
            ForeColor = Color.FromArgb(114, 61, 8),
            Padding = new Padding(12, 10, 12, 4),
            Text = "EXPERIMENTAL: detects selected code, package and Windows executable indicators. " +
                   "Not general antivirus, real-time blocking or a substitute for Microsoft Defender. " +
                   "Never run suspicious files simply because this tool reports no indicators."
        }, 0, 1);

        var selection = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(0, 8, 0, 4)
        };
        selection.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        selection.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        selection.Controls.Add(_selectedPath, 0, 0);
        _selectedPath.Dock = DockStyle.Fill;
        _selectedPath.ReadOnly = true;
        _selectedPath.BackColor = Subtle;
        _selectedPath.BorderStyle = BorderStyle.FixedSingle;
        _selectedPath.PlaceholderText = "Select a file, a folder, or your Downloads folder to scan";

        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            AutoScroll = true,
            Padding = new Padding(0, 2, 0, 0)
        };
        _chooseFile = MakeButton("Choose file", false);
        _chooseFolder = MakeButton("Choose folder", false);
        _downloads = MakeButton("Downloads", false);
        _scan = MakeButton("Scan now", true);
        _cancel = MakeButton("Cancel", false);
        _export = MakeButton("Export JSON", false);
        _watch = MakeButton("Start 60s polling", false);
        _cancel.Enabled = false;
        _scan.Enabled = false;
        _export.Enabled = false;
        foreach (var button in new[] { _chooseFile, _chooseFolder, _downloads, _scan, _cancel, _export, _watch })
            actions.Controls.Add(button);
        InitializeMalwareControls(actions);
        selection.Controls.Add(actions, 0, 1);
        root.Controls.Add(selection, 0, 2);

        var statusPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2 };
        statusPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        statusPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 12));
        _status.Text = "Ready. Select a target; no files are changed by a scan.";
        _status.ForeColor = Navy;
        _status.Dock = DockStyle.Fill;
        _status.Font = new Font("Segoe UI", 10F, FontStyle.Regular);
        statusPanel.Controls.Add(_status, 0, 0);
        _progress.Dock = DockStyle.Fill;
        _progress.Visible = false;
        _progress.Style = ProgressBarStyle.Marquee;
        _progress.MarqueeAnimationSpeed = 20;
        statusPanel.Controls.Add(_progress, 0, 1);
        root.Controls.Add(statusPanel, 0, 3);

        _findings.Dock = DockStyle.Fill;
        _findings.View = View.Details;
        _findings.FullRowSelect = true;
        _findings.GridLines = true;
        _findings.HideSelection = false;
        _findings.MultiSelect = false;
        _findings.Columns.Add("Severity", 105);
        _findings.Columns.Add("Indicator", 240);
        _findings.Columns.Add("File", 260);
        _findings.Columns.Add("Explanation", 420);
        root.Controls.Add(_findings, 0, 4);

        root.Controls.Add(new Label
        {
            Text = "Reports remain on this computer unless you explicitly export or share them. " +
                   "Unsupported files or incomplete coverage must never be treated as clean.",
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = Color.DimGray
        }, 0, 5);

        _chooseFile.Click += (_, _) => ChooseFile();
        _chooseFolder.Click += (_, _) => ChooseFolder();
        _downloads.Click += (_, _) => SelectDownloads();
        _scan.Click += async (_, _) => await ScanOnceAsync();
        _cancel.Click += (_, _) => _scanCancellation?.Cancel();
        _export.Click += (_, _) => ExportReport();
        _watch.Click += (_, _) => ToggleWatch();
        _watchTimer.Tick += async (_, _) => { if (!_running) await ScanOnceAsync(); };
        _findings.SelectedIndexChanged += (_, _) => UpdateQuarantineSelection();
        FormClosing += (_, _) => { _watchTimer.Stop(); _scanCancellation?.Cancel(); };
    }

    private static Button MakeButton(string caption, bool primary) => new()
    {
        Text = caption,
        AutoSize = true,
        Height = 34,
        MinimumSize = new Size(108, 34),
        Padding = new Padding(9, 1, 9, 1),
        Margin = new Padding(0, 1, 8, 2),
        FlatStyle = FlatStyle.Flat,
        BackColor = primary ? Blue : Subtle,
        ForeColor = primary ? Color.White : Navy,
        Cursor = Cursors.Hand
    };

    private void SetTarget(string target)
    {
        if (_running) return;
        _watchTimer.Stop();
        _watch.Text = "Start 60s polling";
        _selectedPath.Text = target;
        ClearClamAvSelections();
        _scan.Enabled = true;
        _status.Text = "Ready to inspect selected target without executing any of its contents.";
    }

    private void ChooseFile()
    {
        using var chooser = new OpenFileDialog { Title = "Select a file to inspect", Filter = "All files (*.*)|*.*", CheckFileExists = true };
        if (chooser.ShowDialog(this) == DialogResult.OK) SetTarget(chooser.FileName);
    }

    private void ChooseFolder()
    {
        using var chooser = new FolderBrowserDialog { Description = "Select a directory for offline inspection", ShowNewFolderButton = false };
        if (chooser.ShowDialog(this) == DialogResult.OK) SetTarget(chooser.SelectedPath);
    }

    private void SelectDownloads()
    {
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (Directory.Exists(downloads)) SetTarget(downloads);
        else MessageBox.Show(this, "Downloads folder was not found. Please select a folder manually.", "DevShield", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void ToggleWatch()
    {
        if (string.IsNullOrWhiteSpace(_selectedPath.Text))
        {
            MessageBox.Show(this, "Select a folder or file first.", "DevShield", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        if (_watchTimer.Enabled)
        {
            _watchTimer.Stop();
            _watch.Text = "Start 60s polling";
            _status.Text = "Polling stopped. Files were not changed.";
        }
        else
        {
            _watchTimer.Start();
            _watch.Text = "Stop polling";
            _status.Text = "60-second polling enabled while this window stays open. Not real-time protection.";
        }
    }

    private async Task ScanOnceAsync()
    {
        if (_running || string.IsNullOrWhiteSpace(_selectedPath.Text)) return;
        var scanner = Path.Combine(AppContext.BaseDirectory, "DevShield-Endpoint.exe");
        if (!File.Exists(scanner))
        {
            _status.Text = "The trusted DevShield-Endpoint.exe engine is missing from this folder.";
            MessageBox.Show(this,
                "Extract the complete DevShield Desktop ZIP to a folder. Keep DevShield-Desktop.exe and DevShield-Endpoint.exe together.",
                "Scanner engine missing", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        ClearClamAvSelections();
        _clamScan.Enabled = false;
        _updateDefinitions.Enabled = false;
        _running = true;
        _scanCancellation = new CancellationTokenSource(TimeSpan.FromMinutes(4));
        _scan.Enabled = false;
        _chooseFile.Enabled = false;
        _chooseFolder.Enabled = false;
        _downloads.Enabled = false;
        _cancel.Enabled = true;
        _watch.Enabled = false;
        _export.Enabled = false;
        _progress.Visible = true;
        _status.Text = "Scanning locally. This application never runs or uploads the selected file.";
        _findings.Items.Clear();
        _lastReport = null;

        try
        {
            var (json, exitCode) = await ExecuteEngineAsync(scanner, _selectedPath.Text, _scanCancellation.Token);
            if (json.Length > 5_000_000) throw new InvalidOperationException("Scanner report exceeded safe size limit.");
            using var document = JsonDocument.Parse(json);
            RenderReport(document.RootElement, exitCode);
            _lastReport = json;
            _export.Enabled = true;
        }
        catch (OperationCanceledException)
        {
            _status.Text = "Scan cancelled or timed out. No clean result has been issued.";
        }
        catch (Exception)
        {
            _status.Text = "Scan failed or was incomplete. No clean result has been issued.";
            MessageBox.Show(this,
                "The scan could not be completed. Check folder access, supported file types, the scanner engine and file-size limits.",
                "Scan not completed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally
        {
            _running = false;
            _progress.Visible = false;
            _scan.Enabled = true;
            _chooseFile.Enabled = true;
            _chooseFolder.Enabled = true;
            _downloads.Enabled = true;
            _cancel.Enabled = false;
            _watch.Enabled = true;
            _clamScan.Enabled = true;
            _updateDefinitions.Enabled = true;
            _scanCancellation.Dispose();
            _scanCancellation = null;
        }
    }

    private static async Task<(string Json, int ExitCode)> ExecuteEngineAsync(string engine, string target, CancellationToken cancellation)
    {
        var start = new ProcessStartInfo
        {
            FileName = engine,
            WorkingDirectory = AppContext.BaseDirectory,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("--path");
        start.ArgumentList.Add(target);
        start.ArgumentList.Add("--format");
        start.ArgumentList.Add("json");
        start.ArgumentList.Add("--fail-on");
        start.ArgumentList.Add("high");

        using var proc = new Process { StartInfo = start };
        if (!proc.Start()) throw new InvalidOperationException("Scanner process did not start");
        using var cancelRegistration = cancellation.Register(() =>
        {
            try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
        });
        var output = proc.StandardOutput.ReadToEndAsync(cancellation);
        var errorOutput = proc.StandardError.ReadToEndAsync(cancellation);
        await proc.WaitForExitAsync(cancellation);
        var json = await output;
        _ = await errorOutput; // Never echo possibly sensitive source paths or OS errors to UI.
        if (proc.ExitCode is not (0 or 1 or 2) || string.IsNullOrWhiteSpace(json))
            throw new InvalidOperationException("No usable JSON report");
        return (json, proc.ExitCode);
    }

    private void RenderReport(JsonElement report, int exitCode)
    {
        var complete = report.TryGetProperty("complete", out var completeness) &&
                       completeness.ValueKind == JsonValueKind.True;
        var filesInspected = ReadInt(report, "filesInspected");
        var total = 0;
        if (report.TryGetProperty("findings", out var findings) && findings.ValueKind == JsonValueKind.Array)
        {
            _findings.BeginUpdate();
            try
            {
                foreach (var item in findings.EnumerateArray())
                {
                    if (total++ >= 500) break;
                    var severity = ReadString(item, "severity");
                    var listItem = new ListViewItem(severity.ToUpperInvariant());
                    listItem.SubItems.Add(ReadString(item, "rule"));
                    listItem.SubItems.Add(ReadString(item, "file"));
                    listItem.SubItems.Add(ReadString(item, "message"));
                    if (severity is "critical" or "high")
                        listItem.BackColor = Color.FromArgb(255, 236, 235);
                    else if (severity == "medium")
                        listItem.BackColor = Color.FromArgb(255, 249, 225);
                    _findings.Items.Add(listItem);
                }
            }
            finally { _findings.EndUpdate(); }
        }
        if (exitCode == 2 || !complete)
        {
            _status.Text = $"INCOMPLETE — inspected {filesInspected} files; {total} indicators. Do not assume uninspected files are safe.";
            _status.ForeColor = Color.DarkRed;
        }
        else if (total > 0)
        {
            _status.Text = $"REVIEW NEEDED — inspected {filesInspected} files; {total} static indicators. These are not proof of infection.";
            _status.ForeColor = Color.DarkOrange;
        }
        else
        {
            _status.Text = $"No known indicators in {filesInspected} inspected files. This is NOT an antivirus safety certificate.";
            _status.ForeColor = Color.DarkGreen;
        }
    }

    private static string ReadString(JsonElement source, string name)
    {
        if (!source.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String) return "";
        var text = value.GetString() ?? "";
        return text.Length > 650 ? text[..650] : text;
    }

    private static int ReadInt(JsonElement source, string name) =>
        source.TryGetProperty(name, out var value) && value.TryGetInt32(out var number) ? number : 0;

    private void ExportReport()
    {
        if (_lastReport == null) return;
        using var dialog = new SaveFileDialog
        {
            Title = "Export local scanner report",
            Filter = "JSON file (*.json)|*.json",
            FileName = $"devshield-report-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json",
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            File.WriteAllText(dialog.FileName, _lastReport);
            _status.Text = "Report exported locally. Review it before sharing; paths and hashes may be sensitive.";
        }
        catch (Exception)
        {
            MessageBox.Show(this, "Could not write the report to that location.", "Export failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
