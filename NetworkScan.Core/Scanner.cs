using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using System.Net.NetworkInformation;

namespace NetworkScan.Core;

public record HostResult
{
    public required IPAddress Address { get; init; }
    public bool Alive { get; init; }
    public List<int> OpenPorts { get; init; } = new();
    public string Hostname { get; set; } = string.Empty;
    public string Vendor { get; set; } = string.Empty;
    public string Model { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string Os { get; set; } = string.Empty;
}

public class ScanOptions
{
    public string? Cidr { get; set; }
    public string? Range { get; set; }
    public string? Ports { get; set; }
    public int Concurrency { get; set; } = 256;
    public int PortConcurrency { get; set; } = 128;
    public int TimeoutMs { get; set; } = 250;
    public bool SkipPorts { get; set; } = false;

    public bool Validate(out string error)
    {
        if (string.IsNullOrWhiteSpace(Cidr) && string.IsNullOrWhiteSpace(Range))
        { error = "Specify CIDR or Range"; return false; }
        if (!string.IsNullOrWhiteSpace(Cidr) && !TryParseCidr(Cidr!, out _, out _))
        { error = "Invalid CIDR"; return false; }
        if (!string.IsNullOrWhiteSpace(Range) && !TryParseRange(Range!, out _, out _))
        { error = "Invalid Range"; return false; }
        if (!string.IsNullOrWhiteSpace(Ports) && !TryParsePorts(Ports!, out _))
        { error = "Invalid Ports"; return false; }
        error = string.Empty; return true;
    }

    public List<IPAddress> ResolveIpList()
    {
        if (!string.IsNullOrWhiteSpace(Cidr) && TryParseCidr(Cidr!, out var net, out var mask))
            return ExpandCidr(net, mask);
        if (!string.IsNullOrWhiteSpace(Range) && TryParseRange(Range!, out var start, out var end))
            return ExpandRange(start, end);
        return new List<IPAddress>();
    }

    public HashSet<int> ResolvePorts()
    {
        if (!string.IsNullOrWhiteSpace(Ports) && TryParsePorts(Ports!, out var set)) return set;
        return new HashSet<int> { 21,22,23,25,53,80,110,139,143,161,443,445,3389 };
    }

    public static bool TryParsePorts(string spec, out HashSet<int> ports)
    {
        ports = new HashSet<int>();
        foreach (var token in spec.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (token.Contains('-'))
            {
                var parts = token.Split('-', 2);
                if (!int.TryParse(parts[0], out var a) || !int.TryParse(parts[1], out var b)) return false;
                if (a < 1 || b > 65535 || b < a) return false;
                for (int p = a; p <= b; p++) ports.Add(p);
            }
            else
            {
                if (!int.TryParse(token, out var p) || p < 1 || p > 65535) return false;
                ports.Add(p);
            }
        }
        return ports.Count > 0;
    }

    public static bool TryParseCidr(string cidr, out IPAddress network, out int prefix)
    {
        network = IPAddress.None; prefix = 0;
        var m = Regex.Match(cidr, @"^(\d+\.\d+\.\d+\.\d+)/(\d{1,2})$");
        if (!m.Success) return false;
        if (!IPAddress.TryParse(m.Groups[1].Value, out var net)) return false;
        if (!int.TryParse(m.Groups[2].Value, out var p) || p < 0 || p > 32) return false;
        network = net; prefix = p; return true;
    }

    public static bool TryParseRange(string range, out IPAddress start, out IPAddress end)
    {
        start = IPAddress.None; end = IPAddress.None;
        var m = Regex.Match(range, @"^(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)$");
        if (!m.Success) return false;
        if (!IPAddress.TryParse(m.Groups[1].Value, out var s)) return false;
        if (!IPAddress.TryParse(m.Groups[2].Value, out var e)) return false;
        var sU = ToUInt(s); var eU = ToUInt(e);
        if (eU < sU) return false;
        start = s; end = e; return true;
    }

    public static List<IPAddress> ExpandCidr(IPAddress network, int prefix)
    {
        var net = ToUInt(network);
        uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var start = net & mask;
        var hostCount = (uint)(1UL << (32 - prefix));
        var list = new List<IPAddress>((int)Math.Min(hostCount, 1_000_000));
        for (uint i = 0; i < hostCount; i++)
        {
            var ip = start + i;
            list.Add(FromUInt(ip));
        }
        return list;
    }

    public static List<IPAddress> ExpandRange(IPAddress start, IPAddress end)
    {
        var s = ToUInt(start); var e = ToUInt(end);
        var list = new List<IPAddress>((int)Math.Min((ulong)(e - s + 1), 1_000_000));
        for (uint i = s; i <= e; i++) list.Add(FromUInt(i));
        return list;
    }

    public static uint ToUInt(IPAddress ip) => BitConverter.ToUInt32(ip.GetAddressBytes().Reverse().ToArray(), 0);
    public static IPAddress FromUInt(uint val) => new IPAddress(BitConverter.GetBytes(val).Reverse().ToArray());
}

public static class NetworkScanner
{
    public static List<string> GetLocalCidrs()
    {
        var items = new List<(string cidr, bool isPrivate, bool hasGw, bool isVirtual, int prefix)>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var name = (nic.Name ?? string.Empty).ToLowerInvariant();
                var desc = (nic.Description ?? string.Empty).ToLowerInvariant();
                string[] virtualKeys = new[]{"virtual","vmware","hyper-v","vethernet","virtualbox","vbox","docker","wsl","tap","tun","wireguard","zerotier","tailscale","npcap","bridge","bluetooth","hamachi","vpn","anyconnect","fortinet","pulse","checkpoint","juniper"};
                bool isVirtual = virtualKeys.Any(k => name.Contains(k) || desc.Contains(k));
                var props = nic.GetIPProperties();
                bool hasGw = props.GatewayAddresses.Any(g => g?.Address?.AddressFamily == AddressFamily.InterNetwork);
                foreach (var u in props.UnicastAddresses)
                {
                    if (u.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    var ip = u.Address;
                    var mask = u.IPv4Mask;
                    if (mask == null) continue;
                    int prefix = CountBits(mask);
                    if (prefix < 8 || prefix > 32) continue;

                    // Robust network calculation using UInt32 helpers (avoids endianness issues)
                    var netIp = ScanOptions.FromUInt(ScanOptions.ToUInt(ip) & ScanOptions.ToUInt(mask));
                    var netStr = NormalizeNetwork(netIp.ToString());
                    if (netStr.StartsWith("169.254.")) continue; // skip link-local
                    if (netStr.StartsWith("0.")) continue; // still-invalid after normalization

                    bool isPriv = IsPrivate(netStr);
                    items.Add(($"{netStr}/{prefix}", isPriv, hasGw, isVirtual, prefix));
                }
            }
        }
        catch { }
        return items
            .GroupBy(x => x.cidr)
            .Select(g => g.First())
            .OrderBy(x => x.isVirtual) // non-virtual first
            .ThenByDescending(x => x.hasGw)
            .ThenByDescending(x => x.isPrivate)
            .ThenBy(x => Math.Abs(x.prefix - 24))
            .ThenBy(x => x.cidr)
            .Select(x => FixCidrString(x.cidr))
            .Where(c => !c.StartsWith("0."))
            .Distinct()
            .ToList();
    }

    // Some Windows drivers/APIs can expose IPv4 mask math with octets reversed
    // for certain virtual adapters. Normalize by flipping octets if the
    // calculated network looks like 0.x.y.z while z != 0.
    static string NormalizeNetwork(string ip)
    {
        var parts = ip.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 4) return ip;
        if (parts[0] == "0" && parts[3] != "0")
            return string.Join('.', parts.Reverse());
        return ip;
    }

    static string FixCidrString(string cidr)
    {
        var m = Regex.Match(cidr, @"^(?<ip>\d+\.\d+\.\d+\.\d+)/(\d{1,2})$");
        if (!m.Success) return cidr;
        var ip = m.Groups["ip"].Value;
        var normalizedIp = NormalizeNetwork(ip);
        if (normalizedIp == ip) return cidr;
        return normalizedIp + cidr.Substring(ip.Length);
    }

    static int CountBits(IPAddress mask)
    {
        int count = 0;
        foreach (var b in mask.GetAddressBytes())
        {
            byte x = b;
            for (int i = 0; i < 8; i++) { count += (x & 0x80) != 0 ? 1 : 0; x <<= 1; }
        }
        return count;
    }

    static bool IsPrivate(string ip)
    {
        if (ip.StartsWith("10.")) return true;
        if (ip.StartsWith("192.168.")) return true;
        var m = Regex.Match(ip, @"^172\.(\d+)\.");
        if (m.Success)
        {
            if (int.TryParse(m.Groups[1].Value, out int second))
                return second >= 16 && second <= 31;
        }
        return false;
    }
    public static async Task<List<HostResult>> ScanAsync(
        ScanOptions opts,
        IProgress<string>? log = null,
        IProgress<(int done, int total)>? pingProgress = null,
        IProgress<(int done, int total)>? hostProgress = null,
        CancellationToken ct = default)
    {
        if (!opts.Validate(out var err)) throw new ArgumentException(err);
        var targets = opts.ResolveIpList();
        log?.Report($"Targets: {targets.Count} IPv4 addresses");
        var alive = await PingSweepAsync(targets, opts, pingProgress, ct);
        log?.Report($"Alive hosts: {alive.Count}");
        List<HostResult> results;
        if (opts.SkipPorts || alive.Count == 0)
            results = alive.Select(ip => new HostResult { Address = ip, Alive = true }).ToList();
        else
            results = await PortScanAsync(alive, opts, log, hostProgress, ct);

        await EnrichAsync(results, opts, log, ct);
        return results;
    }

    public static async Task<List<IPAddress>> PingSweepAsync(List<IPAddress> targets, ScanOptions opts,
        IProgress<(int done, int total)>? progress = null, CancellationToken ct = default)
    {
        var alive = new ConcurrentBag<IPAddress>();
        using var gate = new SemaphoreSlim(Math.Max(1, opts.Concurrency));
        var tasks = new List<Task>();
        int processed = 0; int total = targets.Count;
        foreach (var ip in targets)
        {
            await gate.WaitAsync(ct);
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    using var ping = new Ping();
                    var reply = await ping.SendPingAsync(ip, opts.TimeoutMs);
                    if (reply.Status == IPStatus.Success) alive.Add(ip);
                }
                catch { }
                finally
                {
                    var done = Interlocked.Increment(ref processed);
                    progress?.Report((done, total));
                    gate.Release();
                }
            }, ct));
        }
        await Task.WhenAll(tasks);
        return alive.OrderBy(ip => ip.ToString()).ToList();
    }

    public static async Task EnrichAsync(List<HostResult> results, ScanOptions opts, IProgress<string>? log, CancellationToken ct)
    {
        if (results.Count == 0) return;

        var arp = GetArpCache();
        foreach (var r in results)
        {
            if (arp.TryGetValue(r.Address, out var mac)) r.MacAddress = mac;
            // Fill vendor from MAC OUI (with optional online fallback)
            if (string.IsNullOrWhiteSpace(r.Vendor) && !string.IsNullOrWhiteSpace(r.MacAddress))
            {
                try
                {
                    var v = await MacOuiLookup.GetVendorAsync(r.MacAddress, ct);
                    if (!string.IsNullOrWhiteSpace(v)) r.Vendor = v!;
                }
                catch { }
            }
        }

        using var gate = new SemaphoreSlim(Math.Max(1, Math.Min(64, opts.Concurrency)));
        var tasks = new List<Task>();
        foreach (var r in results)
        {
            await gate.WaitAsync(ct);
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    // Hostname via reverse DNS
                    r.Hostname = await TryReverseDnsAsync(r.Address, opts.TimeoutMs, ct) ?? string.Empty;

                    // NetBIOS (NBNS) fallback on Windows networks
                    if (string.IsNullOrWhiteSpace(r.Hostname))
                    {
                        // Prefer direct NBNS UDP query; fallback to nbtstat tool if needed
                        var (nbName, nbMac) = await TryNetBiosUdpAsync(r.Address, Math.Max(600, opts.TimeoutMs), ct);
                        if (string.IsNullOrWhiteSpace(nbName))
                        {
                            var legacy = await TryNetBiosAsync(r.Address, Math.Max(600, opts.TimeoutMs), ct);
                            nbName = legacy.name; nbMac = legacy.mac;
                        }
                        if (!string.IsNullOrWhiteSpace(nbName)) r.Hostname = nbName!;
                        if (string.IsNullOrWhiteSpace(r.MacAddress) && !string.IsNullOrWhiteSpace(nbMac)) r.MacAddress = nbMac!;
                    }

                    // SNMP if 161 open
                    if (r.OpenPorts.Contains(161))
                    {
                        var (name, descr) = await TrySnmpAsync(r.Address, timeoutMs: Math.Max(500, opts.TimeoutMs), ct);
                        if (!string.IsNullOrWhiteSpace(name) && string.IsNullOrWhiteSpace(r.Hostname)) r.Hostname = name;
                        if (!string.IsNullOrWhiteSpace(descr))
                        {
                            // heuristic split vendor/model from descr
                            r.Model = descr;
                            var vendor = descr.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                            if (!string.IsNullOrWhiteSpace(vendor)) r.Vendor = vendor!;
                        }
                    }

                    // SSDP/UPnP discovery can reveal vendor/model/friendly name
                    if (string.IsNullOrWhiteSpace(r.Vendor) || string.IsNullOrWhiteSpace(r.Model) || string.IsNullOrWhiteSpace(r.Hostname))
                    {
                        var upnp = await TrySsdpAsync(r.Address, Math.Max(1200, opts.TimeoutMs), ct);
                        if (!string.IsNullOrWhiteSpace(upnp.friendlyName) && string.IsNullOrWhiteSpace(r.Hostname)) r.Hostname = upnp.friendlyName!;
                        if (!string.IsNullOrWhiteSpace(upnp.manufacturer) && string.IsNullOrWhiteSpace(r.Vendor)) r.Vendor = upnp.manufacturer!;
                        if (!string.IsNullOrWhiteSpace(upnp.model) && string.IsNullOrWhiteSpace(r.Model)) r.Model = upnp.model!;
                    }

                    // HTTP header/title if web ports open and vendor/model still empty
                    if (string.IsNullOrWhiteSpace(r.Vendor) || string.IsNullOrWhiteSpace(r.Model) || string.IsNullOrWhiteSpace(r.Hostname))
                    {
                        var webPort = new[] { 80, 8080, 8000, 443 }.FirstOrDefault(p => r.OpenPorts.Contains(p));
                        if (webPort != 0)
                        {
                            var info = await TryHttpServerHeaderAsync(r.Address, webPort, Math.Max(1000, opts.TimeoutMs), ct);
                            if (!string.IsNullOrWhiteSpace(info))
                            {
                                if (string.IsNullOrWhiteSpace(r.Model)) r.Model = info;
                                if (string.IsNullOrWhiteSpace(r.Vendor)) r.Vendor = info.Split('/', ' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
                            }

                            // Try to fetch HTML title for friendlier device name (printers/NAS)
                            var title = await TryHttpTitleAsync(r.Address, webPort, Math.Max(1500, opts.TimeoutMs), ct);
                            if (!string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(r.Hostname)) r.Hostname = title!;
                        }
                    }

                    // OS detection heuristics (TTL, banners, and ports)
                    r.Os = await DetectOsAsync(r, Math.Max(500, opts.TimeoutMs), ct);
                }
                catch { }
                finally
                {
                    gate.Release();
                }
            }, ct));
        }
        await Task.WhenAll(tasks);
        log?.Report("Enrichment complete.");
    }

    static async Task<string> DetectOsAsync(HostResult r, int timeoutMs, CancellationToken ct)
    {
        try
        {
            int? ttl = await TryPingTtlAsync(r.Address, timeoutMs, ct);

            string? ssh = null;
            if (r.OpenPorts.Contains(22)) ssh = await TrySshBannerAsync(r.Address, 22, timeoutMs, ct);

            // If SNMP already provided a sysDescr in Model, prefer that
            var source = (r.Model + " " + r.Vendor).ToLowerInvariant();
            if (source.Contains("iphone")) return "iOS (Apple)";
            if (source.Contains("ipad")) return "iOS (Apple)";
            if (source.Contains("mac")) return "macOS (Apple)";
            if (source.Contains("ubuntu")) return "Linux (Ubuntu)";
            if (source.Contains("debian")) return "Linux (Debian)";
            if (source.Contains("linux")) return "Linux";
            if (source.Contains("microsoft-iis") || source.Contains("microsoft")) return "Windows";

            if (!string.IsNullOrWhiteSpace(ssh))
            {
                var s = ssh.ToLowerInvariant();
                if (s.Contains("ubuntu")) return "Linux (Ubuntu)";
                if (s.Contains("debian")) return "Linux (Debian)";
                if (s.Contains("openssh")) return "Linux/Unix";
            }

            // MAC OUI based mobile hints
            var macVendor = MacOuiLookup.GetShortBrand(r.MacAddress);
            if (macVendor == "Apple")
            {
                if (r.Hostname.Contains("iphone", StringComparison.OrdinalIgnoreCase) ||
                    r.Hostname.Contains("ipad", StringComparison.OrdinalIgnoreCase))
                    return "iOS (Apple)";
                if (!r.OpenPorts.Contains(445) && !r.OpenPorts.Contains(22))
                    return ttl.HasValue && ttl.Value <= 80 ? "iOS (Apple)" : "Apple device";
                return "macOS (Apple)";
            }
            if (macVendor == "Samsung") return "Android (Samsung)";
            if (macVendor == "Huawei") return "Android (Huawei)";
            if (macVendor == "Xiaomi") return "Android (Xiaomi)";
            if (macVendor == "OnePlus") return "Android (OnePlus)";
            if (macVendor == "Google") return "Android (Google)";

            if (ttl.HasValue)
            {
                if (ttl.Value >= 100) return r.OpenPorts.Contains(445) ? "Windows" : "Windows/Network";
                if (ttl.Value <= 80) return "Linux/Unix";
            }
        }
        catch { }
        return string.Empty;
    }

    static async Task<int?> TryPingTtlAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var p = new Ping();
            var reply = await p.SendPingAsync(ip, timeoutMs);
            if (reply.Status == IPStatus.Success) return reply.Options?.Ttl;
        }
        catch { }
        return null;
    }

    static async Task<string?> TrySshBannerAsync(IPAddress ip, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            var connect = client.ConnectAsync(ip, port);
            _ = connect.ContinueWith(t => { var _ = t.Exception; }, TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted);
            var done = await Task.WhenAny(connect, Task.Delay(timeoutMs, ct));
            if (done != connect)
            {
                try { client.Dispose(); } catch { }
                return null;
            }
            await connect; // propagate error if any
            using var stream = client.GetStream();
            stream.ReadTimeout = timeoutMs;
            var buf = new byte[256];
            int read = await stream.ReadAsync(buf.AsMemory(0, buf.Length), ct);
            if (read > 0)
            {
                var line = Encoding.ASCII.GetString(buf, 0, read).Trim();
                var eol = line.IndexOf('\n');
                if (eol >= 0) line = line.Substring(0, eol).Trim();
                return line;
            }
        }
        catch { }
        return null;
    }

    // Minimal embedded OUI table for common mobile vendors
    static class MacOuiLookup
    {
        private static readonly Dictionary<string, string> PrefixToVendor = new(StringComparer.OrdinalIgnoreCase)
        {
            // Apple
            ["001CB3"] = "Apple", ["001D4F"] = "Apple", ["001F5B"] = "Apple", ["0021E9"] = "Apple",
            ["002241"] = "Apple", ["002312"] = "Apple", ["002332"] = "Apple", ["002500"] = "Apple",
            ["00254B"] = "Apple", ["0025BC"] = "Apple", ["002608"] = "Apple", ["00264A"] = "Apple",
            ["203CAE"] = "Apple", ["28E02C"] = "Apple", ["3C15C2"] = "Apple", ["40A6D9"] = "Apple",
            ["40F52E"] = "Apple", ["4C8D79"] = "Apple", ["581FAA"] = "Apple", ["60FEC5"] = "Apple",
            ["687F74"] = "Apple", ["70CD60"] = "Apple", ["7C04D0"] = "Apple", ["88C663"] = "Apple",
            ["98B8E3"] = "Apple", ["A45E60"] = "Apple", ["BC92B6"] = "Apple", ["C8BCC8"] = "Apple",
            ["D0E140"] = "Apple", ["E0ACCB"] = "Apple",
            // Samsung
            ["00166C"] = "Samsung", ["001D0F"] = "Samsung", ["001EE8"] = "Samsung", ["002119"] = "Samsung",
            ["0024E9"] = "Samsung", ["10683F"] = "Samsung", ["28ABA4"] = "Samsung", ["5C497D"] = "Samsung",
            ["60A10A"] = "Samsung", ["7021C0"] = "Samsung", ["88F031"] = "Samsung", ["B0C4E7"] = "Samsung",
            // Huawei
            ["001E10"] = "Huawei", ["002568"] = "Huawei", ["609620"] = "Huawei", ["D81C79"] = "Huawei",
            // Xiaomi
            ["742344"] = "Xiaomi", ["64B473"] = "Xiaomi", ["28E31F"] = "Xiaomi", ["64CC2E"] = "Xiaomi",
            // OnePlus
            ["F8B599"] = "OnePlus", ["B4F1DA"] = "OnePlus",
            // Google (Pixel)
            ["3C286D"] = "Google", ["7C2EBD"] = "Google",
        };

        private static readonly Dictionary<string, string> Cache = new(StringComparer.OrdinalIgnoreCase);
        private static readonly HttpClient Http = new(new SocketsHttpHandler { AllowAutoRedirect = true })
        {
            Timeout = TimeSpan.FromMilliseconds(1500)
        };

        public static string? GetVendor(string mac)
        {
            var p = GetPrefix(mac);
            if (p == null) return null;
            return PrefixToVendor.TryGetValue(p, out var v) ? v : null;
        }

        public static async Task<string?> GetVendorAsync(string mac, CancellationToken ct)
        {
            var fromLocal = GetVendor(mac);
            if (!string.IsNullOrWhiteSpace(fromLocal)) return fromLocal;

            // cache online lookups per full MAC prefix to be gentle on services
            var key = (GetPrefix(mac) ?? mac).ToUpperInvariant();
            if (Cache.TryGetValue(key, out var cached)) return cached;

            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"https://api.macvendors.com/{mac}");
                req.Headers.UserAgent.ParseAdd("NetworkScan/1.0");
                using var resp = await Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                if (resp.IsSuccessStatusCode)
                {
                    var text = (await resp.Content.ReadAsStringAsync(ct)).Trim();
                    if (!string.IsNullOrWhiteSpace(text) && !text.StartsWith("errors", StringComparison.OrdinalIgnoreCase))
                    {
                        Cache[key] = text;
                        return text;
                    }
                }
            }
            catch { }
            return null;
        }

        public static string? GetShortBrand(string mac)
        {
            return GetVendor(mac);
        }

        private static string? GetPrefix(string mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return null;
            var hex = new string(mac.Where(c => char.IsLetterOrDigit(c)).ToArray()).ToUpperInvariant();
            if (hex.Length < 6) return null;
            return hex.Substring(0, 6);
        }
    }

    static async Task<string?> TryReverseDnsAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        try
        {
            var t = Dns.GetHostEntryAsync(ip);
            var c = await Task.WhenAny(t, Task.Delay(timeoutMs, ct));
            if (c == t)
            {
                var he = await t;
                return he.HostName;
            }
        }
        catch { }
        return null;
    }

    // Lightweight NetBIOS name lookup using the built-in nbtstat tool (Windows environments)
    // Returns: (hostname, mac) when available
    static async Task<(string? name, string? mac)> TryNetBiosAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "nbtstat",
                Arguments = $"-A {ip}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return (null, null);

            var readTask = p.StandardOutput.ReadToEndAsync();
            var errTask = p.StandardError.ReadToEndAsync();
            var completed = await Task.WhenAny(Task.WhenAll(readTask, errTask), Task.Delay(timeoutMs, ct));
            if (completed is not Task t || t != Task.WhenAll(readTask, errTask))
            {
                try { if (!p.HasExited) p.Kill(true); } catch { }
                return (null, null);
            }
            // ensure process ended
            try { p.WaitForExit(Math.Max(250, timeoutMs / 2)); } catch { }

            var output = (readTask.Result ?? string.Empty).Replace("\r", "");
            if (string.IsNullOrWhiteSpace(output)) return (null, null);

            string? mac = null;
            foreach (var line in output.Split('\n'))
            {
                var mMac = Regex.Match(line, @"MAC Address\s*=\s*([0-9A-Fa-f:-]{12,})");
                if (mMac.Success)
                {
                    mac = mMac.Groups[1].Value.Replace('-', ':').ToLowerInvariant();
                    break;
                }
            }

            // Prefer <20> UNIQUE (Server Service), then <00> UNIQUE (Workstation)
            string? best = null;
            foreach (var line in output.Split('\n'))
            {
                var m = Regex.Match(line, @"^\s*([^\s<]{1,15})\s+<([0-9A-Fa-f]{2})>\s+(UNIQUE|GROUP)\s+Registered");
                if (!m.Success) continue;
                var name = m.Groups[1].Value.Trim();
                var code = m.Groups[2].Value.ToUpperInvariant();
                var kind = m.Groups[3].Value.ToUpperInvariant();
                if (string.IsNullOrWhiteSpace(name)) continue;
                if (code == "20" && kind == "UNIQUE") { best = name; break; }
                if (best == null && code == "00" && kind == "UNIQUE") best = name;
            }

            return (best, mac);
        }
        catch { return (null, null); }
    }

    static async Task<(string? sysName, string? sysDescr)> TrySnmpAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        try
        {
            var endPoint = new IPEndPoint(ip, 161);
            var vList = new List<Variable> {
                new Variable(new ObjectIdentifier("1.3.6.1.2.1.1.5.0")), // sysName.0
                new Variable(new ObjectIdentifier("1.3.6.1.2.1.1.1.0"))  // sysDescr.0
            };
            var result = Messenger.Get(VersionCode.V2, endPoint, new OctetString("public"), vList, timeoutMs);
            string? name = result[0].Data.ToString();
            string? descr = result[1].Data.ToString();
            return (name, descr);
        }
        catch { return (null, null); }
    }

    static async Task<string?> TryHttpServerHeaderAsync(IPAddress ip, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                SslOptions = new System.Net.Security.SslClientAuthenticationOptions { RemoteCertificateValidationCallback = (_, __, ___, ____) => true }
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
            var scheme = port == 443 ? "https" : "http";
            var url = $"{scheme}://{ip}/";
            using var req = new HttpRequestMessage(HttpMethod.Head, url);
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            if (resp.Headers.TryGetValues("Server", out var vals))
                return vals.FirstOrDefault();
        }
        catch { }
        return null;
    }

    static async Task<string?> TryHttpTitleAsync(IPAddress ip, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = true,
                SslOptions = new System.Net.Security.SslClientAuthenticationOptions { RemoteCertificateValidationCallback = (_, __, ___, ____) => true }
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
            var scheme = port == 443 ? "https" : "http";
            var url = $"{scheme}://{ip}/";
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseContentRead, ct);
            var html = await resp.Content.ReadAsStringAsync(ct);
            var m = Regex.Match(html ?? string.Empty, @"<title>\s*(.*?)\s*</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            if (m.Success)
            {
                var title = WebUtility.HtmlDecode(m.Groups[1].Value).Trim();
                if (!string.IsNullOrWhiteSpace(title)) return title;
            }
        }
        catch { }
        return null;
    }

    // Direct NBNS (NetBIOS Name Service) Node Status query to UDP/137
    static async Task<(string? name, string? mac)> TryNetBiosUdpAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = Math.Max(500, timeoutMs);
            udp.Client.SendTimeout = Math.Max(500, timeoutMs);
            var endpoint = new IPEndPoint(ip, 137);

            var txId = (ushort)Random.Shared.Next(0, 0xFFFF);
            var payload = BuildNbnsNodeStatusRequest(txId);
            await udp.SendAsync(payload, payload.Length, endpoint);

            var recvTask = udp.ReceiveAsync();
            var completed = await Task.WhenAny(recvTask.AsTask(), Task.Delay(timeoutMs, ct));
            if (completed != recvTask.AsTask()) return (null, null);
            var resp = recvTask.Result;
            if (!resp.RemoteEndPoint.Address.Equals(ip)) return (null, null);
            return ParseNbnsNodeStatusResponse(resp.Buffer);
        }
        catch { return (null, null); }
    }

    static byte[] BuildNbnsNodeStatusRequest(ushort txId)
    {
        // Header: ID, Flags(0x0000), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        var buf = new List<byte>(100);
        void W(ushort v) { buf.Add((byte)(v >> 8)); buf.Add((byte)(v & 0xFF)); }
        W(txId); W(0x0000); W(0x0001); W(0x0000); W(0x0000); W(0x0000);
        // Question name: special '*' encoded to NetBIOS name (32 chars), label length 0x20, end 0x00
        var encoded = EncodeNetBiosName("*");
        buf.Add(0x20); buf.AddRange(Encoding.ASCII.GetBytes(encoded)); buf.Add(0x00);
        W(0x0021); // TYPE = NBSTAT
        W(0x0001); // CLASS = IN
        return buf.ToArray();
    }

    static string EncodeNetBiosName(string name)
    {
        // Pad to 15 chars, add 0x00 suffix type; map to two ASCII chars per nibble (RFC 1002)
        var bytes = new byte[16];
        var raw = Encoding.ASCII.GetBytes((name ?? string.Empty).ToUpperInvariant());
        int i = 0;
        for (; i < Math.Min(15, raw.Length); i++) bytes[i] = raw[i];
        for (; i < 15; i++) bytes[i] = (byte)' '; // pad spaces
        bytes[15] = 0x00; // suffix

        Span<char> outChars = stackalloc char[32];
        for (int j = 0; j < 16; j++)
        {
            byte b = bytes[j];
            outChars[j * 2 + 0] = (char)('A' + ((b >> 4) & 0x0F));
            outChars[j * 2 + 1] = (char)('A' + (b & 0x0F));
        }
        return new string(outChars);
    }

    static (string? name, string? mac) ParseNbnsNodeStatusResponse(byte[] buf)
    {
        try
        {
            if (buf.Length < 57) return (null, null);
            // Skip header (12) + question (var). Find the number of names from the data part.
            // The response format: Header, Question (optional), Answer RR with RDATA containing
            // NAME COUNT (1 byte), then NAME entries and a 6-byte Unit ID (MAC).

            // Heuristic parse: find the first occurrence of a 0x00 length label terminator followed by TYPE=0x0021
            int i = 12; // start after header
            // Skip QNAME
            if (i >= buf.Length) return (null, null);
            while (i < buf.Length && buf[i] != 0x00) i++;
            i += 1; // null
            if (i + 8 > buf.Length) return (null, null);
            // TYPE, CLASS, TTL(4), RDLENGTH(2)
            i += 8; // TYPE/CLASS/TTL
            if (i + 2 > buf.Length) return (null, null);
            ushort rdlen = (ushort)((buf[i] << 8) | buf[i + 1]);
            i += 2;
            if (i + rdlen > buf.Length) rdlen = (ushort)Math.Max(0, buf.Length - i);
            int start = i;
            if (start + 1 > buf.Length) return (null, null);
            int nameCount = buf[start];
            i = start + 1;
            string? best = null;
            for (int n = 0; n < nameCount && i + 18 <= buf.Length; n++)
            {
                var nameBytes = new byte[15];
                Array.Copy(buf, i, nameBytes, 0, 15); i += 15;
                byte suffix = buf[i++];
                byte flags1 = buf[i++]; byte flags2 = buf[i++]; // 2 bytes flags
                // Flags bit 15 indicates GROUP; we want UNIQUE
                bool isGroup = (flags1 & 0x80) != 0;
                var name = Encoding.ASCII.GetString(nameBytes).Trim();
                string code = suffix.ToString("X2");
                if (!isGroup)
                {
                    if (code == "20") { best = name; break; }
                    if (best == null && code == "00") best = name;
                }
            }
            // Skip to Unit ID (MAC): it's at the end of RDATA: 6 bytes
            int end = start + rdlen;
            string? mac = null;
            if (end - 6 >= 0 && end <= buf.Length)
            {
                var macBytes = new byte[6];
                Array.Copy(buf, end - 6, macBytes, 0, 6);
                mac = string.Join(":", macBytes.Select(b => b.ToString("x2")));
            }
            return (best, mac);
        }
        catch { return (null, null); }
    }

    // Simple SSDP/UPnP probe to enrich vendor/model and friendly name
    static async Task<(string? manufacturer, string? model, string? friendlyName)> TrySsdpAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            udp.Client.ReceiveTimeout = Math.Max(800, timeoutMs);
            udp.Client.SendTimeout = Math.Max(800, timeoutMs);
            var dst = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);
            var req = "M-SEARCH * HTTP/1.1\r\n" +
                      "HOST: 239.255.255.250:1900\r\n" +
                      "MAN: \"ssdp:discover\"\r\n" +
                      "MX: 1\r\n" +
                      "ST: ssdp:all\r\n\r\n";
            var data = Encoding.ASCII.GetBytes(req);
            await udp.SendAsync(data, data.Length, dst);

            var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            string? location = null; string? server = null;
            while (DateTime.UtcNow < deadline)
            {
                var wait = (int)Math.Max(50, (deadline - DateTime.UtcNow).TotalMilliseconds);
                var t = udp.ReceiveAsync();
                var c = await Task.WhenAny(t.AsTask(), Task.Delay(wait, ct));
                if (c != t.AsTask()) break;
                var resp = t.Result;
                if (!resp.RemoteEndPoint.Address.Equals(ip)) continue;
                var text = Encoding.UTF8.GetString(resp.Buffer);
                foreach (var line in text.Split(new[] {"\r\n"}, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (line.StartsWith("LOCATION:", StringComparison.OrdinalIgnoreCase)) location = line.Substring(9).Trim();
                    else if (line.StartsWith("SERVER:", StringComparison.OrdinalIgnoreCase)) server = line.Substring(7).Trim();
                }
                break;
            }

            string? manufacturer = null, model = null, friendly = null;
            if (!string.IsNullOrWhiteSpace(server))
            {
                // Use SERVER header as a hint e.g., "Linux/3.14 UPnP/1.0 product/1.0"
                model ??= server;
            }
            if (!string.IsNullOrWhiteSpace(location))
            {
                try
                {
                    using var http = new HttpClient() { Timeout = TimeSpan.FromMilliseconds(Math.Max(800, timeoutMs)) };
                    var xml = await http.GetStringAsync(location, ct);
                    manufacturer = Regex.Match(xml, @"<manufacturer>\s*(.*?)\s*</manufacturer>", RegexOptions.IgnoreCase | RegexOptions.Singleline).Groups[1].Value.Trim();
                    model = (Regex.Match(xml, @"<modelName>\s*(.*?)\s*</modelName>", RegexOptions.IgnoreCase | RegexOptions.Singleline).Groups[1].Value.Trim())
                            ?? model;
                    friendly = Regex.Match(xml, @"<friendlyName>\s*(.*?)\s*</friendlyName>", RegexOptions.IgnoreCase | RegexOptions.Singleline).Groups[1].Value.Trim();
                    if (string.IsNullOrWhiteSpace(manufacturer)) manufacturer = null;
                    if (string.IsNullOrWhiteSpace(model)) model = null;
                    if (string.IsNullOrWhiteSpace(friendly)) friendly = null;
                }
                catch { }
            }
            return (manufacturer, model, friendly);
        }
        catch { return (null, null, null); }
    }

    static Dictionary<IPAddress, string> GetArpCache()
    {
        var map = new Dictionary<IPAddress, string>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Environment.OSVersion.Platform == PlatformID.Win32NT ? "arp" : "/usr/sbin/arp",
                Arguments = "-a",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi)!;
            var text = p.StandardOutput.ReadToEnd();
            p.WaitForExit(2000);
            var lines = text.Split('\n');
            foreach (var line in lines)
            {
                var m = Regex.Match(line, @"(?<ip>\b\d+\.\d+\.\d+\.\d+\b).*?(?<mac>[0-9a-fA-F:-]{11,})");
                if (!m.Success) continue;
                if (IPAddress.TryParse(m.Groups["ip"].Value, out var ip))
                {
                    var mac = m.Groups["mac"].Value.Replace('-', ':').ToLowerInvariant();
                    map[ip] = mac;
                }
            }
        }
        catch { }
        return map;
    }
    public static async Task<List<HostResult>> PortScanAsync(List<IPAddress> hosts, ScanOptions opts,
        IProgress<string>? log = null,
        IProgress<(int done, int total)>? progress = null,
        CancellationToken ct = default)
    {
        var ports = opts.ResolvePorts();
        log?.Report($"Scanning ports: {PortSetToString(ports)}");

        var results = new ConcurrentBag<HostResult>();
        using var gate = new SemaphoreSlim(Math.Max(1, opts.Concurrency));
        var all = new List<Task>();
        int doneHosts = 0; int totalHosts = hosts.Count;
        foreach (var host in hosts)
        {
            await gate.WaitAsync(ct);
            all.Add(Task.Run(async () =>
            {
                try
                {
                    var open = new List<int>();
                    using var inner = new SemaphoreSlim(Math.Max(1, opts.PortConcurrency));
                    var portTasks = new List<Task>();
                    foreach (var port in ports)
                    {
                        await inner.WaitAsync(ct);
                        portTasks.Add(Task.Run(async () =>
                        {
                            try { if (await IsPortOpenAsync(host, port, opts.TimeoutMs, ct)) lock (open) open.Add(port); }
                            catch { }
                            finally { inner.Release(); }
                        }, ct));
                    }
                    await Task.WhenAll(portTasks);
                    results.Add(new HostResult { Address = host, Alive = true, OpenPorts = open.OrderBy(p => p).ToList() });
                }
                finally
                {
                    var d = Interlocked.Increment(ref doneHosts);
                    progress?.Report((d, totalHosts));
                    gate.Release();
                }
            }, ct));
        }
        await Task.WhenAll(all);
        return results.OrderBy(r => r.Address.ToString()).ToList();
    }

    public static async Task<bool> IsPortOpenAsync(IPAddress ip, int port, int timeoutMs, CancellationToken ct)
    {
        using var client = new TcpClient();
        try
        {
            var connectTask = client.ConnectAsync(ip, port);
            // Ensure any later fault is observed to avoid UnobservedTaskException
            _ = connectTask.ContinueWith(t => { var _ = t.Exception; },
                TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted);
            var timeoutTask = Task.Delay(timeoutMs, ct);
            var completed = await Task.WhenAny(connectTask, timeoutTask);
            if (completed == timeoutTask)
            {
                try { client.Dispose(); } catch { }
                return false;
            }
            await connectTask;
            return client.Connected;
        }
        catch { return false; }
    }

    public static string PortSetToString(HashSet<int> ports)
    {
        var list = ports.OrderBy(p => p).ToList();
        var ranges = new List<string>();
        int start = -1, prev = -1;
        foreach (var p in list)
        {
            if (start == -1) { start = prev = p; }
            else if (p == prev + 1) { prev = p; }
            else { ranges.Add(start == prev ? start.ToString() : $"{start}-{prev}"); start = prev = p; }
        }
        if (start != -1) ranges.Add(start == prev ? start.ToString() : $"{start}-{prev}");
        return string.Join(',', ranges);
    }
}
