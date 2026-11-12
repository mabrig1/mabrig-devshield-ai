using System.Diagnostics;
using System.Drawing;
using System.Text.Json;
using System.Windows.Forms;

namespace Mabrig.DevShieldDesktop;

// Monitor only THIS laptop. No packets captured, remote ports probed,
// credentials collected, persistent background service, or cloud telemetry.
internal sealed class NetworkMonitorForm : Form
{
    private readonly Label _summary = new();
    private readonly Label _status = new();
    private readonly ListView _adapters = new();
    private readonly ListView _connections = new();
    private readonly ListView _ports = new();
    private readonly TextBox _security = new();
    private readonly Button _refresh = MakeButton("Refresh now");
    private readonly Button _monitor = MakeButton("Start 5s monitor");
    private readonly Button _export = MakeButton("Export local JSON");
    private readonly Button _checkSecurity = MakeButton("Check Windows Security");
    private readonly Button _openSecurity = MakeButton("Open Windows Security");
    private readonly Button _openUpdate = MakeButton("Open Windows Update");
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 5000 };
    private readonly Dictionary<string, (long Rx, long Tx, DateTimeOffset At)> _previous = new();
    private CancellationTokenSource? _securityCts;
    private NetworkSnapshot? _last;
    private bool _refreshing;
    private bool _closed;

    internal NetworkMonitorForm()
    {
        Text = "DevShield — Laptop & Network Security Monitor";
        Width = 1160;
        Height = 810;
        MinimumSize = new Size(870, 630);
        StartPosition = FormStartPosition.CenterParent;
        BackColor = Color.White;
        Font = new Font("Segoe UI", 9F);
        ShowIcon = false;

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, RowCount = 5, ColumnCount = 1,
            Padding = new Padding(18, 12, 18, 12)
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 84));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 56));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 74));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
        Controls.Add(root);

        var heading = new Panel { Dock = DockStyle.Fill };
        heading.Controls.Add(new Label
        {
            Dock = DockStyle.Top, Height = 42,
            Font = new Font("Segoe UI", 16, FontStyle.Bold),
            ForeColor = Color.FromArgb(15, 37, 68),
            Text = "Laptop & Network Security Monitor"
        });
        heading.Controls.Add(new Label
        {
            Dock = DockStyle.Bottom, Height = 37,
            ForeColor = Color.DimGray,
            Text = "Passive live view of THIS Windows laptop: Wi-Fi/Ethernet/VPN adapters, TCP connections, listening ports and device protection."
        });
        root.Controls.Add(heading, 0, 0);

        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true, AutoScroll = true
        };
        foreach (var b in new[] { _refresh, _monitor, _export,
            _checkSecurity, _openSecurity, _openUpdate })
            actions.Controls.Add(b);
        root.Controls.Add(actions, 0, 1);

        var summaryPanel = new Panel { Dock = DockStyle.Fill };
        _summary.Dock = DockStyle.Top;
        _summary.Height = 34;
        _summary.Font = new Font("Segoe UI", 10, FontStyle.Bold);
        _summary.Text = "No network snapshot collected yet.";
        _summary.ForeColor = Color.FromArgb(22, 56, 101);
        _status.Dock = DockStyle.Bottom;
        _status.Height = 35;
        _status.ForeColor = Color.FromArgb(120, 83, 10);
        _status.Text = "Passive monitoring is OFF. No network traffic leaves this application.";
        summaryPanel.Controls.Add(_summary);
        summaryPanel.Controls.Add(_status);
        root.Controls.Add(summaryPanel, 0, 2);

        var tabs = new TabControl { Dock = DockStyle.Fill };
        root.Controls.Add(tabs, 0, 3);
        tabs.TabPages.Add(MakeTab("Adapters & traffic", _adapters, new[] {
            ("Interface", 190), ("Type / state", 170), ("Addresses", 230),
            ("Gateway", 170), ("DNS servers", 230), ("Received/s", 110), ("Sent/s", 110)
        }));
        tabs.TabPages.Add(MakeTab("TCP connections", _connections, new[] {
            ("Local endpoint", 210), ("Remote endpoint", 250),
            ("State", 130), ("Remote scope", 190)
        }));
        tabs.TabPages.Add(MakeTab("Listening services", _ports, new[] {
            ("Protocol", 115), ("Bound address and port", 260),
            ("Review status", 265)
        }));

        var securityPage = new TabPage("Windows security & developer checklist");
        var securityRoot = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2,
            Padding = new Padding(10, 9, 10, 10)
        };
        securityRoot.RowStyles.Add(new RowStyle(SizeType.Absolute, 160));
        securityRoot.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        _security.Multiline = true;
        _security.ReadOnly = true;
        _security.BorderStyle = BorderStyle.None;
        _security.ScrollBars = ScrollBars.Vertical;
        _security.Dock = DockStyle.Fill;
        _security.BackColor = Color.White;
        _security.Font = new Font("Consolas", 9.5F);
        _security.Text = "Windows Defender and firewall status not checked.\r\n" +
            "Click 'Check Windows Security' to query local first-party Windows APIs.\r\n" +
            "Unknown results are not equivalent to enabled or disabled protection.\r\n" +
            "Do not disable Microsoft Defender for DevShield.";
        securityRoot.Controls.Add(_security, 0, 0);
        securityRoot.Controls.Add(new Label
        {
            Dock = DockStyle.Fill, AutoSize = false,
            Font = new Font("Segoe UI", 10),
            Text = "VIBE-CODING LAPTOP SECURITY CHECKLIST\r\n\r\n" +
                   "1. Keep Microsoft Defender real-time protection, Firewall and Windows Update enabled.\r\n\r\n" +
                   "2. Enable BitLocker / Device Encryption if supported. Back up important projects regularly.\r\n\r\n" +
                   "3. Use a standard user account for daily coding, not an administrator account.\r\n\r\n" +
                   "4. Use passkeys/MFA for GitHub and Cloudflare; never commit API keys or .env files.\r\n\r\n" +
                   "5. Review downloaded GitHub projects and package install hooks BEFORE running them.\r\n\r\n" +
                   "6. Keep browsers, VS Code, Node.js, Git and Windows patched. Avoid unknown IDE extensions.\r\n\r\n" +
                   "7. Prefer trusted networks; use WPA2/WPA3 Wi-Fi and change default router credentials.\r\n\r\n" +
                   "8. Investigate unusual listeners or unfamiliar outbound connections using Windows Task Manager and Firewall.\r\n\r\n" +
                   "DevShield observes local endpoints only; it cannot identify a hacker, inspect your entire router, " +
                   "attribute connections to individual processes or guarantee an uncompromised laptop."
        }, 0, 1);
        securityPage.Controls.Add(securityRoot);
        tabs.TabPages.Add(securityPage);

        root.Controls.Add(new Label
        {
            Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = Color.DimGray,
            Text = "No packet sniffing, process killing, remote scans, password collection or cloud uploads. " +
                   "IP addresses in an exported report may be private: review before sharing."
        }, 0, 4);

        _refresh.Click += async (_, _) => await RefreshAsync();
        _monitor.Click += (_, _) => ToggleMonitor();
        _export.Click += (_, _) => ExportSnapshot();
        _checkSecurity.Click += async (_, _) => await CheckSecurityAsync();
        _openSecurity.Click += (_, _) => OpenWindowsSettings("windowsdefender:");
        _openUpdate.Click += (_, _) => OpenWindowsSettings("ms-settings:windowsupdate");
        _timer.Tick += async (_, _) => await RefreshAsync();
        FormClosing += (_, _) =>
        {
            _closed = true;
            _timer.Stop();
            _securityCts?.Cancel();
        };
        Shown += async (_, _) => await RefreshAsync();
    }

    private static Button MakeButton(string label) => new()
    {
        AutoSize = true, MinimumSize = new Size(115, 33),
        Text = label, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand,
        BackColor = Color.FromArgb(244, 248, 253),
        ForeColor = Color.FromArgb(15, 37, 68),
        Margin = new Padding(0, 2, 9, 1),
        Padding = new Padding(7, 0, 7, 0)
    };

    private static TabPage MakeTab(string title, ListView list,
        IEnumerable<(string Label, int Width)> columns)
    {
        list.Dock = DockStyle.Fill;
        list.View = View.Details;
        list.FullRowSelect = true;
        list.GridLines = true;
        list.HideSelection = false;
        list.MultiSelect = false;
        foreach (var c in columns)
            list.Columns.Add(c.Label, c.Width);
        var page = new TabPage(title);
        page.Controls.Add(list);
        return page;
    }

    private static string FormatBytesPerSecond(double bytes)
    {
        if (double.IsNaN(bytes) || double.IsInfinity(bytes) || bytes < 0) return "Unknown";
        return bytes >= 1048576 ? (bytes / 1048576).ToString("F1") + " MiB/s" :
               bytes >= 1024 ? (bytes / 1024).ToString("F1") + " KiB/s" :
               bytes.ToString("F0") + " B/s";
    }

    private async Task RefreshAsync()
    {
        if (_closed || _refreshing) return;
        _refreshing = true;
        _refresh.Enabled = false;
        try
        {
            var snapshot = await Task.Run(NetworkTelemetry.Capture);
            if (_closed || IsDisposed) return;
            _last = snapshot;
            Render(snapshot);
        }
        catch
        {
            if (!_closed && !IsDisposed)
                _status.Text = "Unable to collect network telemetry. Status unknown; check Windows settings.";
        }
        finally
        {
            _refreshing = false;
            if (!_closed && !IsDisposed) _refresh.Enabled = true;
        }
    }

    private void Render(NetworkSnapshot snapshot)
    {
        _adapters.BeginUpdate();
        _connections.BeginUpdate();
        _ports.BeginUpdate();
        try
        {
            _adapters.Items.Clear();
            foreach (var nic in snapshot.Interfaces)
            {
                string inbound = "First sample";
                string outbound = "First sample";
                if (_previous.TryGetValue(nic.Key, out var p))
                {
                    var elapsed = (snapshot.CapturedUtc - p.At).TotalSeconds;
                    if (elapsed >= 1 && nic.BytesReceived >= p.Rx && nic.BytesSent >= p.Tx)
                    {
                        inbound = FormatBytesPerSecond((nic.BytesReceived - p.Rx) / elapsed);
                        outbound = FormatBytesPerSecond((nic.BytesSent - p.Tx) / elapsed);
                    }
                    else
                        inbound = outbound = "Counter reset / unknown";
                }
                _previous[nic.Key] = (nic.BytesReceived, nic.BytesSent, snapshot.CapturedUtc);
                var item = new ListViewItem(nic.Name);
                item.SubItems.Add(nic.Kind + " / " + nic.Status +
                    (nic.LinkMbps > 0 ? " / " + nic.LinkMbps + " Mbps" : ""));
                item.SubItems.Add(nic.Addresses);
                item.SubItems.Add(nic.Gateways);
                item.SubItems.Add(nic.DnsServers);
                item.SubItems.Add(inbound);
                item.SubItems.Add(outbound);
                if (nic.Status != "Up") item.ForeColor = Color.Gray;
                _adapters.Items.Add(item);
            }

            _connections.Items.Clear();
            foreach (var c in snapshot.Connections)
            {
                var item = new ListViewItem(c.LocalEndpoint);
                item.SubItems.Add(c.RemoteEndpoint);
                item.SubItems.Add(c.TcpState);
                item.SubItems.Add(c.RemoteScope);
                _connections.Items.Add(item);
            }
            _ports.Items.Clear();
            foreach (var p in snapshot.ListeningPorts)
            {
                var item = new ListViewItem(p.Protocol);
                item.SubItems.Add(p.Endpoint);
                item.SubItems.Add(p.BindingScope);
                if (p.BindingScope == "Review reachable binding")
                    item.BackColor = Color.FromArgb(255, 246, 220);
                _ports.Items.Add(item);
            }
        }
        finally
        {
            _adapters.EndUpdate();
            _connections.EndUpdate();
            _ports.EndUpdate();
        }

        int active = snapshot.Interfaces.Count(x => x.Status == "Up");
        int external = snapshot.Connections.Count(x => x.RemoteScope == "external-or-routed");
        int broad = snapshot.ListeningPorts.Count(x => x.BindingScope == "Review reachable binding");
        _summary.Text = "Adapters active: " + active +
            "    TCP connections: " + snapshot.ObservedTcpConnections +
            "    External/routed endpoints: " + external +
            "    Listening ports: " + snapshot.ObservedListeningPorts +
            "    Broad bindings: " + broad;
        string note = snapshot.Notices.Count > 0 ? string.Join("  ", snapshot.Notices.Take(2)) :
            "No interface/listener collection errors observed. Normal browsing creates external connections.";
        _status.Text = (snapshot.Complete ? "Snapshot collected" : "PARTIAL SNAPSHOT") +
            " at " + snapshot.CapturedUtc.ToLocalTime().ToString("HH:mm:ss") + ". " + note;
        _status.ForeColor = snapshot.Complete ? Color.FromArgb(18, 84, 65) : Color.DarkRed;
    }

    private void ToggleMonitor()
    {
        if (_timer.Enabled)
        {
            _timer.Stop();
            _monitor.Text = "Start 5s monitor";
            _status.Text = "Live sampling stopped. Existing snapshot remains in memory.";
        }
        else
        {
            _timer.Start();
            _monitor.Text = "Stop monitor";
            _status.Text = "Live sampling enabled every five seconds while this window is open.";
            _ = RefreshAsync();
        }
    }

    private void ExportSnapshot()
    {
        if (_last is null)
        {
            MessageBox.Show(this, "Collect a network snapshot first.", "No snapshot",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        if (MessageBox.Show(this,
            "Your network snapshot includes LOCAL AND REMOTE IP addresses, adapter names and listening ports. " +
            "These may reveal private infrastructure and activity. It will be saved ONLY to a file you select; no upload. Export?",
            "Export potentially sensitive network information",
            MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        using var chooser = new SaveFileDialog
        {
            Title = "Save local network snapshot",
            Filter = "JSON file (*.json)|*.json",
            FileName = "devshield-network-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + ".json",
            OverwritePrompt = true
        };
        if (chooser.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            File.WriteAllText(chooser.FileName, JsonSerializer.Serialize(
                new { schemaVersion = 1, scope = "local-laptop-only",
                    warning = "Read-only observations, not malicious activity attribution",
                    snapshot = _last }, new JsonSerializerOptions { WriteIndented = true }));
            _status.Text = "Saved locally. Review addresses and connection data before sharing.";
        }
        catch
        {
            MessageBox.Show(this, "Could not save to the selected location.",
                "Export failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private async Task CheckSecurityAsync()
    {
        if (_securityCts is not null) return;
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(18));
        _securityCts = cts;
        _checkSecurity.Enabled = false;
        _security.Text = "Querying Windows Defender and Firewall (read-only, no admin elevation)...";
        try
        {
            var result = await LaptopProtection.CheckAsync(cts.Token);
            if (_closed || IsDisposed) return;
            static string Status(bool? value) => value is null ? "UNKNOWN" :
                value.Value ? "Enabled (Windows reports)" : "DISABLED (review Windows Security)";
            var lines = new List<string>
            {
                "WINDOWS SECURITY — LOCAL READ-ONLY STATUS",
                "Antivirus enabled:  " + Status(result.AntivirusEnabled),
                "Real-time protection:  " + Status(result.RealtimeProtectionEnabled),
                "Antimalware service:  " + Status(result.AntimalwareServiceEnabled),
                "Defender signature age:  " + result.SignatureAge
            };
            foreach (var firewall in result.FirewallProfiles)
                lines.Add("Windows Firewall (" + firewall.Name + "):  " + Status(firewall.Enabled));
            lines.Add("");
            lines.Add(result.Availability);
            lines.Add("A missing or unusual status is NOT evidence of infection. Confirm in Windows Security.");
            _security.Text = string.Join(Environment.NewLine, lines);
        }
        catch (OperationCanceledException)
        {
            if (!_closed && !IsDisposed) _security.Text =
                "Windows Security query timed out or cancelled; statuses remain UNKNOWN.";
        }
        finally
        {
            cts.Dispose();
            _securityCts = null;
            if (!_closed && !IsDisposed) _checkSecurity.Enabled = true;
        }
    }

    private void OpenWindowsSettings(string uri)
    {
        // Fixed, first-party Windows settings protocols. Never accept a caller URL.
        if (uri != "windowsdefender:" && uri != "ms-settings:windowsupdate") return;
        try
        {
            Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true });
        }
        catch
        {
            MessageBox.Show(this,
                "Windows could not open that settings page. Open Windows Settings manually.",
                "Settings unavailable", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
