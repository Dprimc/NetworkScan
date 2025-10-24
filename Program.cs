using NetworkScan.Core;
using System.Text;

// Console front-end for NetworkScan.Core
// Examples:
//   dotnet run -- --cidr 192.168.1.0/24 --ports 22,80,443 --json results.json
//   dotnet run -- --range 192.168.1.10-192.168.1.50 --ports 1-1024 --csv results.csv

var (showHelp, auto, cli, outJson, outCsv) = ParseArgs(args);
if (showHelp)
{
    PrintHelp();
    return;
}

if (auto && string.IsNullOrWhiteSpace(cli.Cidr) && string.IsNullOrWhiteSpace(cli.Range))
{
    var local = NetworkScanner.GetLocalCidrs();
    if (local.Count > 0) cli.Cidr = local[0];
}

if (!cli.Validate(out var error))
{
    Console.Error.WriteLine($"Error: {error}\n");
    PrintHelp();
    Environment.ExitCode = 2;
    return;
}

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (s, e) => { e.Cancel = true; cts.Cancel(); };

var log = new Progress<string>(s => Console.WriteLine(s));
var pingProg = new Progress<(int done, int total)>(p =>
{
    if (p.total > 0 && p.done % Math.Max(1, p.total / 10) == 0)
        Console.WriteLine($"Ping progress: {p.done}/{p.total}...");
});
var hostProg = new Progress<(int done, int total)>(p =>
{
    Console.WriteLine($"Port scan: {p.done}/{p.total} hosts");
});

var results = await NetworkScanner.ScanAsync(cli, log, pingProg, hostProg, cts.Token);
RenderTable(results);

if (!string.IsNullOrWhiteSpace(outJson)) await SaveJsonAsync(results, outJson, cts.Token);
if (!string.IsNullOrWhiteSpace(outCsv)) await SaveCsvAsync(results, outCsv, cts.Token);

static (bool showHelp, bool auto, ScanOptions opts, string? json, string? csv) ParseArgs(string[] args)
{
    var o = new ScanOptions();
    bool showHelp = false; bool auto = false; string? json = null; string? csv = null;
    for (int i = 0; i < args.Length; i++)
    {
        var a = args[i];
        string? Next() => (i + 1 < args.Length) ? args[++i] : null;
        switch (a)
        {
            case "-h":
            case "--help": showHelp = true; break;
            case "--auto": auto = true; break;
            case "--cidr": o.Cidr = Next(); break;
            case "--range": o.Range = Next(); break;
            case "--ports": o.Ports = Next(); break;
            case "--concurrency": if (int.TryParse(Next(), out var c)) o.Concurrency = Math.Max(1, c); break;
            case "--port-concurrency": if (int.TryParse(Next(), out var pc)) o.PortConcurrency = Math.Max(1, pc); break;
            case "--timeout": if (int.TryParse(Next(), out var t)) o.TimeoutMs = Math.Max(50, t); break;
            case "--skip-ports": o.SkipPorts = true; break;
            case "--json": json = Next(); break;
            case "--csv": csv = Next(); break;
            default: Console.Error.WriteLine($"Unknown argument: {a}"); showHelp = true; break;
        }
    }
    return (showHelp, auto, o, json, csv);
}

static void PrintHelp()
{
    Console.WriteLine("NetworkScan - fast IPv4 network scanner (console)");
    Console.WriteLine();
    Console.WriteLine("Usage:");
    Console.WriteLine("  dotnet run -- --cidr <IP/CIDR> [options]");
    Console.WriteLine("  dotnet run -- --range <start-end> [options]");
    Console.WriteLine();
    Console.WriteLine("Options:");
    Console.WriteLine("  --auto                     use first active local subnet");
    Console.WriteLine("  --cidr <CIDR>              e.g., 192.168.1.0/24");
    Console.WriteLine("  --range <start-end>        e.g., 192.168.1.10-192.168.1.50");
    Console.WriteLine("  --ports <list|range>       e.g., 22,80,443 or 1-1024");
    Console.WriteLine("  --concurrency <n>          parallel hosts (default 256)");
    Console.WriteLine("  --port-concurrency <n>     parallel ports per host (128)");
    Console.WriteLine("  --timeout <ms>             timeout per ping/connect (250)");
    Console.WriteLine("  --skip-ports               only ping sweep");
    Console.WriteLine("  --json <file>              save JSON report");
    Console.WriteLine("  --csv <file>               save CSV report");
}

static void RenderTable(List<HostResult> results)
{
    if (results.Count == 0) { Console.WriteLine("No results."); return; }
    Console.WriteLine();
    Console.WriteLine($"Results ({results.Count} hosts):");
    Console.WriteLine("IP Address       Alive  Name                          OS                   Vendor               Model                Open Ports");
    Console.WriteLine("---------------- -----  ---------------------------- -------------------- -------------------- -------------------- ----------");
    foreach (var r in results)
    {
        var ports = r.OpenPorts?.Count > 0 ? string.Join(',', r.OpenPorts) : "-";
        Console.WriteLine($"{r.Address,-16} {(r.Alive ? "Yes" : "No"),-5} {Trunc(r.Hostname,28),-28} {Trunc(r.Os,20),-20} {Trunc(r.Vendor,20),-20} {Trunc(r.Model,20),-20} {ports}");
    }
}

static async Task SaveJsonAsync(List<HostResult> results, string path, CancellationToken ct)
{
    var json = System.Text.Json.JsonSerializer.Serialize(results.Select(r => new
    {
        ip = r.Address.ToString(),
        alive = r.Alive,
        name = r.Hostname,
        vendor = r.Vendor,
        model = r.Model,
        os = r.Os,
        mac = r.MacAddress,
        openPorts = r.OpenPorts
    }), new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    await File.WriteAllTextAsync(path, json, ct);
    Console.WriteLine($"Saved JSON: {path}");
}

static async Task SaveCsvAsync(List<HostResult> results, string path, CancellationToken ct)
{
    var sb = new StringBuilder().AppendLine("ip,alive,name,os,vendor,model,mac,open_ports");
    foreach (var r in results)
    {
        var ports = r.OpenPorts != null && r.OpenPorts.Count > 0 ? string.Join(' ', r.OpenPorts) : string.Empty;
        sb.AppendLine($"{r.Address},{(r.Alive ? 1 : 0)},\"{r.Hostname}\",\"{r.Os}\",\"{r.Vendor}\",\"{r.Model}\",{r.MacAddress},{ports}");
    }
    await File.WriteAllTextAsync(path, sb.ToString(), ct);
    Console.WriteLine($"Saved CSV: {path}");
}

static string Trunc(string s, int len)
{
    if (string.IsNullOrEmpty(s)) return "";
    return s.Length <= len ? s : s.Substring(0, len - 1) + "…";
}
