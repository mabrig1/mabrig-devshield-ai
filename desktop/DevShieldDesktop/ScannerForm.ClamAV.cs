using System.Drawing;
using System.Windows.Forms;

namespace Mabrig.DevShieldDesktop;

internal sealed partial class ScannerForm
{
    private readonly Button _clamInstall = MakeButton("Set ClamAV folder", false);
    private readonly Button _clamScan = MakeButton("Virus definition scan", true);
    private readonly Button _updateDefinitions = MakeButton("Update definitions", false);
    private readonly Button _quarantine = MakeButton("Quarantine selected", false);
    private readonly Button _restoreQuarantine = MakeButton("Restore...", false);
    private string? _clamFolder;

    private void InitializeMalwareControls(FlowLayoutPanel actions)
    {
        foreach (var button in new[] {
            _clamInstall, _updateDefinitions, _clamScan, _quarantine, _restoreQuarantine
        }) actions.Controls.Add(button);

        _clamFolder = ClamAvIntegration.FindInstallFolder();
        _clamScan.Enabled = false;
        _quarantine.Enabled = false;
        _clamInstall.Click += (_, _) => ChooseClamAvFolder();
        _updateDefinitions.Click += async (_, _) => await UpdateVirusDefinitionsAsync();
        _clamScan.Click += async (_, _) => await RunClamAvScanAsync();
        _quarantine.Click += (_, _) => QuarantineSelected();
        _restoreQuarantine.Click += (_, _) => RestoreQuarantined();
        _clamInstall.Text = _clamFolder is null ? "Set ClamAV folder" : "ClamAV configured";
    }

    private void ClearClamAvSelections()
    {
        _quarantine.Enabled = false;
        _clamScan.Enabled = !_running && !string.IsNullOrWhiteSpace(_selectedPath.Text);
    }

    private void UpdateQuarantineSelection()
    {
        _quarantine.Enabled = !_running && _findings.SelectedItems.Count == 1 &&
            _findings.SelectedItems[0].Tag is ClamDetection d &&
            QuarantineStore.IsEligible(d);
    }

    private void ChooseClamAvFolder()
    {
        if (_running) return;
        using var chooser = new FolderBrowserDialog
        {
            Description = "Choose an OFFICIAL installed ClamAV folder containing both clamscan.exe and freshclam.exe. Do not select unknown downloaded executables.",
            ShowNewFolderButton = false
        };
        if (chooser.ShowDialog(this) != DialogResult.OK) return;
        if (!ClamAvIntegration.IsValidInstallFolder(chooser.SelectedPath))
        {
            _status.Text = "ClamAV not found: official clamscan.exe and freshclam.exe are required.";
            MessageBox.Show(this, "Install official ClamAV for Windows from clamav.net/downloads, then select its installation folder. Do not use files from unknown GitHub mirrors.",
                "ClamAV engine unavailable", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        _clamFolder = chooser.SelectedPath;
        _clamInstall.Text = "ClamAV configured";
        _status.Text = "Official ClamAV integration selected. " +
            (ClamAvIntegration.DefinitionsStatus() ?? "Virus definitions not installed. Click Update definitions.");
    }

    private bool EnsureClamAvailable()
    {
        _clamFolder ??= ClamAvIntegration.FindInstallFolder();
        if (_clamFolder is not null && ClamAvIntegration.IsValidInstallFolder(_clamFolder))
            return true;
        MessageBox.Show(this, "ClamAV is an optional external open-source antivirus engine.\n\nInstall the official Windows x64 edition from https://www.clamav.net/downloads, then use Set ClamAV folder in this app. No installation or download is performed automatically.",
            "Official ClamAV not installed", MessageBoxButtons.OK, MessageBoxIcon.Information);
        return false;
    }

    private void SetBusy(string message, bool busy)
    {
        _running = busy;
        _progress.Visible = busy;
        _status.Text = message;
        _scan.Enabled = !busy && !string.IsNullOrWhiteSpace(_selectedPath.Text);
        _clamScan.Enabled = !busy && !string.IsNullOrWhiteSpace(_selectedPath.Text);
        _updateDefinitions.Enabled = !busy;
        _chooseFile.Enabled = !busy;
        _chooseFolder.Enabled = !busy;
        _downloads.Enabled = !busy;
        _clamInstall.Enabled = !busy;
        _watch.Enabled = !busy;
        _cancel.Enabled = busy;
        _restoreQuarantine.Enabled = !busy;
        UpdateQuarantineSelection();
    }

    private async Task UpdateVirusDefinitionsAsync()
    {
        if (_running || !EnsureClamAvailable()) return;
        var confirmation = MessageBox.Show(this,
            "FreshClam will contact Cisco Talos's official ClamAV signature update servers and store definitions locally. It will not upload your files. Continue?",
            "Update official virus definitions", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
        if (confirmation != DialogResult.Yes) return;
        using var cancel = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        _scanCancellation = cancel;
        SetBusy("Updating official ClamAV virus definitions through FreshClam...", true);
        try
        {
            var result = await ClamAvIntegration.UpdateDefinitionsAsync(_clamFolder!, cancel.Token);
            SetBusy(result.Status, false);
            if (!result.Success)
                MessageBox.Show(this, result.Status +
                    "\n\nCheck that the official ClamAV installer is configured and the network permits FreshClam updates.",
                    "Definitions not updated", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            else
                MessageBox.Show(this, "Official malware definitions are now available.\n" +
                    (ClamAvIntegration.DefinitionsStatus() ?? ""),
                    "Definition update succeeded", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (OperationCanceledException)
        {
            SetBusy("Virus definition update cancelled or timed out. Check the existing database status.", false);
        }
        finally { _scanCancellation = null; }
    }

    private async Task RunClamAvScanAsync()
    {
        if (_running || string.IsNullOrWhiteSpace(_selectedPath.Text) || !EnsureClamAvailable()) return;
        if (ClamAvIntegration.DefinitionsStatus() is null)
        {
            MessageBox.Show(this, "No official virus definitions have been installed for this app.\nClick Update definitions before scanning.",
                "Definitions required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var folder = _clamFolder!;
        var target = _selectedPath.Text;
        var token = new CancellationTokenSource(TimeSpan.FromMinutes(15));
        _scanCancellation = token;
        _export.Enabled = false;
        _lastReport = null;
        _findings.Items.Clear();
        SetBusy("ClamAV is scanning with updated signatures. No infected files will be deleted automatically.", true);
        try
        {
            var outcome = await ClamAvIntegration.ScanAsync(folder, target, token.Token);
            _findings.BeginUpdate();
            try
            {
                foreach (var detection in outcome.Detections)
                {
                    var item = new ListViewItem("MALWARE");
                    item.SubItems.Add(detection.Signature);
                    item.SubItems.Add(detection.FilePath);
                    item.SubItems.Add("Official ClamAV signature match. Review and select Quarantine if appropriate.");
                    item.BackColor = Color.FromArgb(255, 227, 226);
                    item.Tag = detection;
                    _findings.Items.Add(item);
                }
            }
            finally { _findings.EndUpdate(); }
            SetBusy(outcome.Status +
                " " + outcome.Detections.Count + " detection(s). " +
                "Only explicitly selected hits in your own Downloads, Desktop or Documents can be quarantined.", false);
            _status.ForeColor = outcome.Complete
                ? (outcome.Detections.Count > 0 ? Color.DarkRed : Color.DarkGreen)
                : Color.DarkRed;
            if (!outcome.Complete)
                MessageBox.Show(this,
                    "ClamAV did not fully complete. Some files may be skipped, unsupported or larger than engine limits. Treat unknown files as untrusted.",
                    "Incomplete virus scan", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (OperationCanceledException)
        {
            SetBusy("ClamAV scan cancelled or timed out. No clean verdict issued.", false);
        }
        finally { _scanCancellation = null; token.Dispose(); }
    }

    private void QuarantineSelected()
    {
        if (_running || _findings.SelectedItems.Count != 1 ||
            _findings.SelectedItems[0].Tag is not ClamDetection detection) return;
        if (!QuarantineStore.IsEligible(detection))
        {
            MessageBox.Show(this, "Only original user files under Downloads, Desktop or Documents on the local system drive can be quarantined. The file must be unchanged and from an official ClamAV detection.",
                "Quarantine restricted", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (MessageBox.Show(this,
            "ClamAV detected: " + detection.Signature + "\n\nFile: " + detection.FilePath +
            "\n\nMove this file to a private, reversible quarantine? This may disrupt programs depending on the file. No files are permanently deleted.",
            "Confirm quarantine", MessageBoxButtons.YesNo, MessageBoxIcon.Warning)
            != DialogResult.Yes) return;
        try
        {
            var entry = QuarantineStore.Quarantine(detection);
            _status.Text = "Quarantined 1 confirmed signature hit: " + entry.Signature +
                ". To recover, choose Restore after reviewing the risk.";
            _findings.SelectedItems[0].Tag = null;
            _quarantine.Enabled = false;
        }
        catch (Exception)
        {
            MessageBox.Show(this,
                "The file could not be safely quarantined. It may have changed, moved or be in a protected directory. Rescan it and use your established antivirus for system-wide cleanup.",
                "Quarantine failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void RestoreQuarantined()
    {
        if (_running) return;
        var entries = QuarantineStore.List();
        if (entries.Count == 0)
        {
            MessageBox.Show(this, "There are no recoverable DevShield quarantine records.",
                "Quarantine", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var picker = new Form
        {
            Text = "DevShield quarantine — select an item to restore",
            Width = 790, Height = 390, StartPosition = FormStartPosition.CenterParent,
            Font = Font
        };
        var options = new ListBox { Dock = DockStyle.Fill };
        foreach (var entry in entries)
            options.Items.Add($"{entry.QuarantinedUtc:u} | {entry.Signature} | {entry.OriginalPath}");
        var restore = new Button
        {
            Dock = DockStyle.Bottom, Height = 43, Text = "Review selected and restore to original location",
            DialogResult = DialogResult.OK
        };
        picker.Controls.Add(options);
        picker.Controls.Add(restore);
        picker.AcceptButton = restore;
        if (picker.ShowDialog(this) != DialogResult.OK ||
            options.SelectedIndex < 0 || options.SelectedIndex >= entries.Count) return;
        var selected = entries[options.SelectedIndex];
        if (MessageBox.Show(this, "Restoring a quarantined file may reintroduce malware.\n\n" +
            "Threat: " + selected.Signature + "\nPath: " + selected.OriginalPath +
            "\n\nRestore this exact file? DevShield will NOT execute it.",
            "Final restoration confirmation", MessageBoxButtons.YesNo, MessageBoxIcon.Warning)
            != DialogResult.Yes) return;
        try
        {
            QuarantineStore.Restore(selected);
            _status.Text = "File restored without execution. Do not open it until an independent security review.";
        }
        catch (Exception)
        {
            MessageBox.Show(this, "Restoration refused: unsafe path, changed hash, missing data or an existing destination file.",
                "Restore failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
