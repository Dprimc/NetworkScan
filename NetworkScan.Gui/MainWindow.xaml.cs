using NetworkScan.Core;
using System.Collections.ObjectModel;
using System.Text;
using System.Windows;
using System.IO;

namespace NetworkScan.Gui;

public partial class MainWindow : Window
{
    private CancellationTokenSource? _cts;
    public ObservableCollection<Row> Results { get; } = new();

    public MainWindow()
    {
        InitializeComponent();
        ResultsGrid.DataContext = this;
        ResultsGrid.ItemsSource = Results;
        SetupContextMenu();
        ToggleButtons(isRunning: false);
        LoadLocalCidrs();
    }

    private async void StartBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_cts != null) return;
        Results.Clear();
        LogBox.Clear();
        var opts = new ScanOptions
        {
            Cidr = string.IsNullOrWhiteSpace(CidrBox.Text) ? null : CidrBox.Text,
            Range = string.IsNullOrWhiteSpace(RangeBox.Text) ? null : RangeBox.Text,
            Ports = string.IsNullOrWhiteSpace(PortsBox.Text) ? null : PortsBox.Text,
            Concurrency = int.TryParse(HostConcBox.Text, out var hc) ? Math.Max(1, hc) : 256,
            PortConcurrency = int.TryParse(PortConcBox.Text, out var pc) ? Math.Max(1, pc) : 128,
            TimeoutMs = int.TryParse(TimeoutBox.Text, out var to) ? Math.Max(50, to) : 250,
            SkipPorts = (bool)SkipPortsBox.IsChecked!
        };

        if (!opts.Validate(out var error))
        {
            AppendLog($"Error: {error}");
            return;
        }

        _cts = new CancellationTokenSource();
        ToggleButtons(isRunning: true);
        try
        {
            var log = new Progress<string>(s => AppendLog(s));
            var pingProg = new Progress<(int done, int total)>(p =>
            {
                if (p.total > 0 && p.done % Math.Max(1, p.total / 10) == 0)
                    AppendLog($"Ping progress: {p.done}/{p.total}...");
            });
            var hostProg = new Progress<(int done, int total)>(p => AppendLog($"Port scan: {p.done}/{p.total} hosts"));

            var results = await NetworkScanner.ScanAsync(opts, log, pingProg, hostProg, _cts.Token);
                foreach (var r in results)
                {
                    Results.Add(new Row
                    {
                        Address = r.Address.ToString(),
                        Alive = r.Alive,
                        Name = r.Hostname,
                        Os = r.Os,
                        Vendor = r.Vendor,
                        Model = r.Model,
                        Mac = r.MacAddress,
                        PortsText = (r.OpenPorts != null && r.OpenPorts.Count > 0) ? string.Join(',', r.OpenPorts) : "-"
                    });
                }
            AppendLog($"Done. Hosts: {Results.Count}");
        }
        catch (OperationCanceledException)
        {
            AppendLog("Canceled.");
        }
        catch (Exception ex)
        {
            AppendLog($"Error: {ex.Message}");
        }
        finally
        {
            _cts?.Dispose();
            _cts = null;
            ToggleButtons(isRunning: false);
        }
    }

    private void CancelBtn_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
    }

    private void DetectBtn_Click(object sender, RoutedEventArgs e)
    {
        LoadLocalCidrs();
    }

    private void LoadLocalCidrs()
    {
        try
        {
            var cidrs = NetworkScanner.GetLocalCidrs();
            CidrBox.Items.Clear();
            foreach (var c in cidrs) CidrBox.Items.Add(c);
            AppendLog($"Detected networks: {string.Join(", ", cidrs)}");
            if (cidrs.Count > 0) CidrBox.Text = cidrs[0];
        }
        catch { }
    }

    private async void SaveJsonBtn_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog { Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*", DefaultExt = ".json" };
            if (dlg.ShowDialog(this) == true)
            {
                var json = System.Text.Json.JsonSerializer.Serialize(Results.Select(r => new { ip = r.Address, alive = r.Alive, name = r.Name, os = r.Os, vendor = r.Vendor, model = r.Model, mac = r.Mac, openPorts = r.PortsText }), new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(dlg.FileName, json);
                AppendLog($"Saved JSON: {dlg.FileName}");
            }
    }

    private async void SaveCsvBtn_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog { Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*", DefaultExt = ".csv" };
            if (dlg.ShowDialog(this) == true)
            {
                var sb = new StringBuilder().AppendLine("ip,alive,name,os,vendor,model,mac,open_ports");
                foreach (var r in Results)
                    sb.AppendLine($"{r.Address},{(r.Alive ? 1 : 0)},\"{r.Name}\",\"{r.Os}\",\"{r.Vendor}\",\"{r.Model}\",{r.Mac},{r.PortsText.Replace(',', ' ')}");
                await File.WriteAllTextAsync(dlg.FileName, sb.ToString());
                AppendLog($"Saved CSV: {dlg.FileName}");
            }
    }

    private void ToggleButtons(bool isRunning)
    {
        StartBtn.IsEnabled = !isRunning;
        CancelBtn.IsEnabled = isRunning;
        SaveJsonBtn.IsEnabled = !isRunning && Results.Count > 0;
        SaveCsvBtn.IsEnabled = !isRunning && Results.Count > 0;
    }

    private void AppendLog(string text)
    {
        LogBox.AppendText(text + Environment.NewLine);
        LogBox.ScrollToEnd();
    }

    // Context menu helpers
    private void SetupContextMenu()
    {
        var menu = new System.Windows.Controls.ContextMenu();
        var copyIp = new System.Windows.Controls.MenuItem { Header = "Copy IP" };
        copyIp.Click += (_, __) =>
        {
            if (ResultsGrid.SelectedItem is Row r && !string.IsNullOrWhiteSpace(r.Address))
            { Clipboard.SetText(r.Address); AppendLog($"Copied IP: {r.Address}"); }
        };
        var copyMac = new System.Windows.Controls.MenuItem { Header = "Copy MAC" };
        copyMac.Click += (_, __) =>
        {
            if (ResultsGrid.SelectedItem is Row r && !string.IsNullOrWhiteSpace(r.Mac))
            { Clipboard.SetText(r.Mac); AppendLog($"Copied MAC: {r.Mac}"); }
        };
        menu.Items.Add(copyIp);
        menu.Items.Add(copyMac);
        ResultsGrid.ContextMenu = menu;

        ResultsGrid.PreviewMouseRightButtonDown += (s, e) =>
        {
            var dep = e.OriginalSource as DependencyObject;
            while (dep != null && dep is not System.Windows.Controls.DataGridRow)
                dep = System.Windows.Media.VisualTreeHelper.GetParent(dep);
            if (dep is System.Windows.Controls.DataGridRow row)
            {
                row.IsSelected = true;
            }
        };
    }

    public class Row
    {
        public string Address { get; set; } = "";
        public bool Alive { get; set; }
        public string Name { get; set; } = "";
        public string Os { get; set; } = "";
        public string Vendor { get; set; } = "";
        public string Model { get; set; } = "";
        public string Mac { get; set; } = "";
        public string PortsText { get; set; } = "";
    }
}
