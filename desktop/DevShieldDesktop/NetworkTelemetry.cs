using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Mabrig.DevShieldDesktop;

// Passive, local-only snapshots. No socket connections, packet capture, Wi-Fi
// password reads, router access, process injection, DNS lookups, or API calls.
// Raw IP addresses are visible only to the user in the local GUI/export.
internal sealed record DeviceInterface(
    string Key, string Name, string Kind, string Status, long LinkMbps,
    string Addresses, string Gateways, string DnsServers,
    long BytesReceived, long BytesSent);
internal sealed record TcpObservation(
    string LocalEndpoint, string RemoteEndpoint, string TcpState, string RemoteScope);
internal sealed record PortObservation(string Protocol, string Endpoint, string BindingScope);
internal sealed record NetworkSnapshot(
    DateTimeOffset CapturedUtc, IReadOnlyList<DeviceInterface> Interfaces,
    IReadOnlyList<TcpObservation> Connections, IReadOnlyList<PortObservation> ListeningPorts,
    int ObservedTcpConnections, int ObservedListeningPorts,
    bool Complete, IReadOnlyList<string> Notices);

internal static class NetworkTelemetry
{
    private const int MaxInterfaces = 64;
    private const int MaxConnections = 1500;
    private const int MaxListeners = 500;

    internal static string ClassifyScope(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return "loopback";
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            return "all-interfaces";
        if (address.Equals(IPAddress.None) || address.Equals(IPAddress.IPv6None))
            return "unspecified";
        if (address.IsIPv6Multicast || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal)
            return "local-network";
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = address.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC) return "local-network"; // IPv6 ULA
            if (address.IsIPv4MappedToIPv6)
                return ClassifyScope(address.MapToIPv4());
            return "external-or-routed";
        }
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            if (b[0] == 10 || b[0] == 127 ||
                (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                (b[0] == 192 && b[1] == 168) ||
                (b[0] == 169 && b[1] == 254) ||
                (b[0] == 100 && b[1] >= 64 && b[1] <= 127) ||
                (b[0] == 198 && (b[1] == 18 || b[1] == 19)) ||
                b[0] >= 224)
                return "local-network";
            return "external-or-routed";
        }
        return "unknown";
    }

    internal static bool IsBroadlyBound(IPAddress address) =>
        ClassifyScope(address) is "all-interfaces" or "external-or-routed";

    internal static NetworkSnapshot Capture()
    {
        var interfaces = new List<DeviceInterface>();
        var connections = new List<TcpObservation>();
        var listeners = new List<PortObservation>();
        var notices = new List<string>();
        var complete = true;
        var allTcp = 0;
        var allListeners = 0;

        try
        {
            var nics = NetworkInterface.GetAllNetworkInterfaces()
                .OrderBy(n => n.Name, StringComparer.OrdinalIgnoreCase).ToArray();
            if (nics.Length > MaxInterfaces)
            {
                complete = false;
                notices.Add("Adapter display is capped; additional adapters were not shown.");
            }
            foreach (var nic in nics.Take(MaxInterfaces))
            {
                try
                {
                    var properties = nic.GetIPProperties();
                    long rx = 0, tx = 0;
                    try
                    {
                        var traffic = nic.GetIPv4Statistics();
                        rx = Math.Max(0, traffic.BytesReceived);
                        tx = Math.Max(0, traffic.BytesSent);
                    }
                    catch { /* Some adapters do not supply counters. */ }
                    var addrs = properties.UnicastAddresses
                        .Select(a => a.Address.ToString()).Take(12).ToArray();
                    var gateway = properties.GatewayAddresses
                        .Select(g => g.Address.ToString()).Take(6).ToArray();
                    var dns = properties.DnsAddresses
                        .Select(x => x.ToString()).Take(6).ToArray();
                    interfaces.Add(new(
                        nic.Id, nic.Name, nic.NetworkInterfaceType.ToString(),
                        nic.OperationalStatus.ToString(), Math.Max(0, nic.Speed / 1_000_000),
                        string.Join(", ", addrs), string.Join(", ", gateway),
                        string.Join(", ", dns), rx, tx));
                }
                catch
                {
                    complete = false;
                    notices.Add("One network adapter could not be inspected.");
                }
            }
        }
        catch
        {
            complete = false;
            notices.Add("Network adapter enumeration failed.");
        }

        try
        {
            var global = IPGlobalProperties.GetIPGlobalProperties();
            var tcp = global.GetActiveTcpConnections();
            allTcp = tcp.Length;
            if (tcp.Length > MaxConnections)
            {
                complete = false;
                notices.Add("TCP connection display is capped; some entries were omitted.");
            }
            foreach (var c in tcp.Take(MaxConnections))
            {
                connections.Add(new(
                    c.LocalEndPoint.ToString(),
                    c.RemoteEndPoint.ToString(),
                    c.State.ToString(),
                    ClassifyScope(c.RemoteEndPoint.Address)));
            }

            var tcpListeners = global.GetActiveTcpListeners();
            var udpListeners = global.GetActiveUdpListeners();
            allListeners = tcpListeners.Length + udpListeners.Length;
            if (allListeners > MaxListeners)
            {
                complete = false;
                notices.Add("Listener display is capped; some ports were omitted.");
            }
            foreach (var endpoint in tcpListeners.Take(MaxListeners))
                listeners.Add(new("TCP", endpoint.ToString(),
                    IsBroadlyBound(endpoint.Address) ? "Review reachable binding" : "Local/restricted binding"));
            foreach (var endpoint in udpListeners.Take(Math.Max(0, MaxListeners - listeners.Count)))
                listeners.Add(new("UDP", endpoint.ToString(),
                    IsBroadlyBound(endpoint.Address) ? "Review reachable binding" : "Local/restricted binding"));
        }
        catch
        {
            complete = false;
            notices.Add("Windows did not provide complete TCP/UDP connection information.");
        }
        if (interfaces.All(n => n.Status != OperationalStatus.Up.ToString()))
            notices.Add("No active network interface was reported. Check Wi-Fi or Ethernet settings.");
        if (listeners.Any(l => l.BindingScope == "Review reachable binding"))
            notices.Add("Some services listen on non-loopback addresses. This is common; check Windows Firewall and each service before treating it as a risk.");
        return new(DateTimeOffset.UtcNow, interfaces, connections, listeners,
            allTcp, allListeners, complete, notices);
    }

    internal static bool SelfTest()
    {
        bool[] expected = [
            ClassifyScope(IPAddress.Parse("127.0.0.1")) == "loopback",
            ClassifyScope(IPAddress.Parse("192.168.1.2")) == "local-network",
            ClassifyScope(IPAddress.Parse("10.2.3.4")) == "local-network",
            ClassifyScope(IPAddress.Parse("172.31.4.2")) == "local-network",
            ClassifyScope(IPAddress.Parse("100.77.1.1")) == "local-network",
            ClassifyScope(IPAddress.Parse("8.8.8.8")) == "external-or-routed",
            ClassifyScope(IPAddress.Parse("::1")) == "loopback",
            ClassifyScope(IPAddress.Parse("fc00::1")) == "local-network",
            ClassifyScope(IPAddress.Parse("fe80::1")) == "local-network",
            ClassifyScope(IPAddress.Any) == "all-interfaces",
            IsBroadlyBound(IPAddress.Any),
            !IsBroadlyBound(IPAddress.Loopback)
        ];
        return expected.All(x => x);
    }
}
