// MainWindow.xaml.cs
using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;

namespace PacketSnifferWPF
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private ObservableCollection<PacketInfo> _packets = new ObservableCollection<PacketInfo>();
        private ICollectionView _packetsView; // view with filter
        private ICaptureDevice _device;
        private List<int> _monitoredPorts;
        private bool _debugMode;
        private StreamWriter _simpleLogWriter;
        private StreamWriter _fullPayloadWriter;
        private CancellationTokenSource _cancellationTokenSource;
        private bool _monitorAllPorts;

        // Compiled regex patterns for better performance
        private static readonly Regex HttpRequestRegex = new Regex(
            @"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP/([0-9.]+)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindow"/> class.
        /// Sets up the UI, data bindings, and event handlers.
        /// </summary>
        public MainWindow()
        {
            InitializeComponent();

            // set items source and build collection view for filtering
            PacketsDataGrid.ItemsSource = _packets;
            _packetsView = CollectionViewSource.GetDefaultView(_packets);
            _packetsView.Filter = PacketFilter;

            // Set up ports mode ComboBox
            PortsModeComboBox.ItemsSource = new List<string> { "all", "common", "targeted", "custom" };
            PortsModeComboBox.SelectedIndex = 2; // Default to "targeted"
            PortsModeComboBox.SelectionChanged += PortsModeComboBox_SelectionChanged;

            // Hook up protocol filter initial event (in case user changes later)
            ProtocolFilterComboBox.SelectionChanged += FilterControlChanged;
            OnlyWithPayloadCheckBox.Checked += FilterControlChanged;
            OnlyWithPayloadCheckBox.Unchecked += FilterControlChanged;

            LoadInterfaces();
        }

        /// <summary>
        /// Handles changes to filter controls, refreshing the packet view.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RoutedEventArgs"/> instance containing the event data.</param>
        private void FilterControlChanged(object sender, RoutedEventArgs e)
        {
            _packetsView?.Refresh();
        }

        /// <summary>
        /// Handles changes to the protocol filter ComboBox, refreshing the packet view.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="SelectionChangedEventArgs"/> instance containing the event data.</param>
        private void FilterControlChanged(object sender, SelectionChangedEventArgs e)
        {
            _packetsView?.Refresh();
        }

        /// <summary>
        /// Filters packets for display based on protocol and payload settings.
        /// </summary>
        /// <param name="obj">The packet object to evaluate.</param>
        /// <returns>True if the packet passes the filter; otherwise, false.</returns>
        private bool PacketFilter(object obj)
        {
            if (obj is PacketInfo p)
            {
                // payload filter
                if (OnlyWithPayloadCheckBox.IsChecked == true && !p.HasPayload)
                    return false;

                // protocol filter
                var selected = (ProtocolFilterComboBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All";
                if (!string.Equals(selected, "All", StringComparison.OrdinalIgnoreCase))
                {
                    if (!string.Equals(p.Protocol, selected, StringComparison.OrdinalIgnoreCase))
                        return false;
                }

                return true;
            }
            return false;
        }

        /// <summary>
        /// Handles changes to the PortsModeComboBox, enabling/disabling the custom ports input.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="SelectionChangedEventArgs"/> instance containing the event data.</param>
        private void PortsModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PortsModeComboBox.SelectedItem != null)
            {
                CustomPortsTextBox.IsEnabled = PortsModeComboBox.SelectedItem.ToString() == "custom";
            }
        }

        /// <summary>
        /// Loads available loopback network interfaces into the InterfaceComboBox.
        /// </summary>
        private void LoadInterfaces()
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count == 0)
            {
                MessageBox.Show("No interfaces found! Ensure Npcap is installed and run as admin.");
                return;
            }

            // Filter to only loopback interfaces (matches "Adapter for loopback traffic capture" or "Npcap Loopback Adapter")
            var loopbackDevices = devices.Where(d =>
                d.Description.Contains("loopback", StringComparison.OrdinalIgnoreCase) ||
                d.Name.Contains("lo", StringComparison.OrdinalIgnoreCase)).ToList();

            if (loopbackDevices.Count == 0)
            {
                MessageBox.Show("No loopback interface found! Ensure Npcap is installed with loopback support and run as admin.");
                return;
            }

            InterfaceComboBox.ItemsSource = loopbackDevices.Select(d => d.Description).ToList();
            InterfaceComboBox.SelectedIndex = 0; // Default to the first (and likely only) loopback interface
        }

        /// <summary>
        /// Starts packet sniffing when the Start button is clicked.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RoutedEventArgs"/> instance containing the event data.</param>
        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            if (InterfaceComboBox.SelectedItem == null)
            {
                MessageBox.Show("Select an interface.");
                return;
            }

            // Get ports arg from new controls
            string portsArg = PortsModeComboBox.SelectedItem.ToString();
            if (portsArg == "custom")
            {
                portsArg = CustomPortsTextBox.Text.Trim();
                if (string.IsNullOrEmpty(portsArg))
                {
                    MessageBox.Show("Enter comma-separated ports for custom mode.");
                    return;
                }
            }

            // Parse ports
            try
            {
                (_monitoredPorts, _monitorAllPorts) = ParsePorts(portsArg);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Invalid ports: {ex.Message}");
                return;
            }

            _debugMode = DebugCheckBox.IsChecked ?? false;
            var selectedIndex = InterfaceComboBox.SelectedIndex;
            var selectedInterface = CaptureDeviceList.Instance.Where(d =>
                d.Description.Contains("loopback", StringComparison.OrdinalIgnoreCase) ||
                d.Name.Contains("lo", StringComparison.OrdinalIgnoreCase)).ToList()[selectedIndex]; // Retrieve based on filtered list

            // Open log files
            try
            {
                _simpleLogWriter = new StreamWriter(LogFileTextBox.Text, true, Encoding.UTF8);
                _fullPayloadWriter = new StreamWriter("captured_packets_full.txt", true, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open log files: {ex.Message}");
                return;
            }

            // Start sniffing on background thread
            _cancellationTokenSource = new CancellationTokenSource();
            Task.Run(() => StartSniffing(selectedInterface, _cancellationTokenSource.Token));

            StartButton.IsEnabled = false;
            StopButton.IsEnabled = true;
        }

        /// <summary>
        /// Stops packet sniffing and closes log files when the Stop button is clicked.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="RoutedEventArgs"/> instance containing the event data.</param>
        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            _simpleLogWriter?.Close();
            _fullPayloadWriter?.Close();
            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
        }

        /// <summary>
        /// Parses the ports argument to determine which ports to monitor.
        /// </summary>
        /// <param name="portsArg">The ports mode or custom port list.</param>
        /// <returns>A tuple containing the list of ports and a boolean indicating if all ports are monitored.</returns>
        /// <exception cref="ArgumentException">Thrown if the ports format is invalid.</exception>
        private (List<int>, bool) ParsePorts(string portsArg)
        {
            if (portsArg.Equals("all", StringComparison.OrdinalIgnoreCase))
                return (null, true);

            if (portsArg.Equals("common", StringComparison.OrdinalIgnoreCase))
                return (new List<int> { 80, 443, 8000, 8080, 8888 }, false);

            if (portsArg.Equals("targeted", StringComparison.OrdinalIgnoreCase))
                return (new List<int> { 5000, 8080 }, false);

            try
            {
                var ports = portsArg.Split(',').Select(p => int.Parse(p.Trim())).ToList();
                return (ports, false);
            }
            catch
            {
                throw new ArgumentException("Invalid ports format. Use 'all', 'common', 'targeted', or comma-separated ints.");
            }
        }

        /// <summary>
        /// Starts the packet sniffing process on the specified device.
        /// </summary>
        /// <param name="device">The capture device to use.</param>
        /// <param name="token">The cancellation token to stop sniffing.</param>
        private void StartSniffing(ICaptureDevice device, CancellationToken token)
        {
            // Ensure we only attach the handler once
            device.OnPacketArrival -= Device_OnPacketArrival;
            device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);

            try
            {
                device.Open(DeviceModes.Promiscuous, 1000); // 1s read timeout
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                    MessageBox.Show($"Failed to open device: {ex.GetType().Name}: {ex.Message}")
                );
                try { _simpleLogWriter?.WriteLine($"[Open device error] {ex.GetType().Name}: {ex.Message}"); _simpleLogWriter?.Flush(); } catch { }
                return;
            }

            // Build a valid BPF filter: one port token per port and include both tcp and udp.
            string filter = "tcp or udp";
            if (!_monitorAllPorts && _monitoredPorts != null && _monitoredPorts.Count > 0)
            {
                var tokens = new List<string>();
                foreach (var p in _monitoredPorts)
                {
                    // Only add valid port numbers
                    if (p > 0 && p <= 65535)
                    {
                        tokens.Add($"tcp port {p}");
                        tokens.Add($"udp port {p}");
                    }
                }
                if (tokens.Count > 0)
                    filter = string.Join(" or ", tokens);
            }

            try
            {
                // Setting device.Filter may throw for invalid filter expressions.
                device.Filter = filter;
                _simpleLogWriter?.WriteLine($"[Sniffer] Applied filter: {filter}");
                _simpleLogWriter?.Flush();
            }
            catch (Exception ex)
            {
                // If filter fails, log and continue capturing without filter so we still get traffic.
                try
                {
                    _simpleLogWriter?.WriteLine($"[Filter error] {ex.GetType().Name}: {ex.Message} - continuing without filter");
                    _simpleLogWriter?.Flush();
                }
                catch { }

                try { device.Filter = ""; } catch { } // best effort: clear filter
            }

            try
            {
                device.StartCapture();
                _simpleLogWriter?.WriteLine($"[Sniffer] Started capture on: {device.Description}");
                _simpleLogWriter?.Flush();
            }
            catch (Exception ex)
            {
                try { _simpleLogWriter?.WriteLine($"[StartCapture error] {ex.GetType().Name}: {ex.Message}"); _simpleLogWriter?.Flush(); } catch { }
                Dispatcher.Invoke(() =>
                    MessageBox.Show($"Failed to start capture: {ex.Message}")
                );
                return;
            }

            // Loop until cancellation requested
            try
            {
                while (!token.IsCancellationRequested)
                {
                    Thread.Sleep(100);
                }
            }
            finally
            {
                try
                {
                    device.StopCapture();
                    device.Close();
                    _simpleLogWriter?.WriteLine("[Sniffer] Stopped capture and closed device");
                    _simpleLogWriter?.Flush();
                }
                catch (Exception ex)
                {
                    try { _simpleLogWriter?.WriteLine($"[Stop/Close error] {ex.GetType().Name}: {ex.Message}"); _simpleLogWriter?.Flush(); } catch { }
                }
            }
        }

        /// <summary>
        /// Handles packet arrival events, parsing and processing packets.
        /// </summary>
        /// <param name="sender">The source of the event.</param>
        /// <param name="e">The <see cref="PacketCapture"/> instance containing the packet data.</param>
        private void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                var raw = e.GetPacket();
                var packet = PacketDotNet.Packet.ParsePacket(raw.LinkLayerType, raw.Data);

                // Try to parse IP layer
                var ipPacket = packet.Extract<IPPacket>();
                string srcIp = ipPacket?.SourceAddress?.ToString() ?? "(unknown)";
                string dstIp = ipPacket?.DestinationAddress?.ToString() ?? "(unknown)";

                // Try TCP/UDP
                var tcp = packet.Extract<TcpPacket>();
                var udp = packet.Extract<UdpPacket>();

                int srcPort = 0, dstPort = 0;
                string protocolLabel = "Unknown";
                string decodedPayload = null;

                if (tcp != null)
                {
                    srcPort = tcp.SourcePort;
                    dstPort = tcp.DestinationPort;
                    protocolLabel = "TCP";
                    if (tcp.PayloadData != null && tcp.PayloadData.Length > 0)
                    {
                        try { decodedPayload = Encoding.UTF8.GetString(tcp.PayloadData); }
                        catch { decodedPayload = BitConverter.ToString(tcp.PayloadData); }
                    }
                }
                else if (udp != null)
                {
                    srcPort = udp.SourcePort;
                    dstPort = udp.DestinationPort;
                    protocolLabel = "UDP";
                    if (udp.PayloadData != null && udp.PayloadData.Length > 0)
                    {
                        try { decodedPayload = Encoding.UTF8.GetString(udp.PayloadData); }
                        catch { decodedPayload = BitConverter.ToString(udp.PayloadData); }
                    }
                }
                else
                {
                    // Not TCP/UDP — ignore for now
                    return;
                }

                // Respect monitored ports if configured
                if (!_monitorAllPorts && _monitoredPorts != null && _monitoredPorts.Count > 0)
                {
                    bool match = (_monitoredPorts.Contains(srcPort) || _monitoredPorts.Contains(dstPort));
                    if (!match) return; // not one of the ports we wanted
                }

                // Normalize protocol label further if HTTP-like data detected
                var httpLabel = DetectHttpLabel(decodedPayload);
                if (!string.IsNullOrEmpty(httpLabel)) protocolLabel = httpLabel;

                // If both ports are zero but we have payload, still proceed
                if (srcPort == 0 && dstPort == 0 && string.IsNullOrEmpty(decodedPayload))
                    return;

                // Now hand off to UI/logging
                ProcessPacket(srcIp, srcPort, dstIp, dstPort, decodedPayload, protocolLabel, packet, tcp);
            }
            catch (Exception ex)
            {
                // Log any handler exception to the simple log so it's visible for debugging
                try
                {
                    var msg = $"[Handler error {DateTime.Now:yyyy-MM-dd HH:mm:ss}] {ex.GetType().Name}: {ex.Message}";
                    _simpleLogWriter?.WriteLine(msg);
                    _simpleLogWriter?.Flush();
                }
                catch { }
            }
        }

        /// <summary>
        /// Detects if the payload contains HTTP data and returns an appropriate label.
        /// </summary>
        /// <param name="payload">The packet payload to analyze.</param>
        /// <returns>An HTTP-specific label or null if not HTTP.</returns>
        private string DetectHttpLabel(string payload)
        {
            if (string.IsNullOrEmpty(payload)) return null;

            // Regex.Replace pattern: ^[\r\n]+
            // ^           : Anchor at start of the string
            // [\r\n]+    : One or more CR or LF characters (covers Windows "\r\n" or lone \n/\r) — strips leading blank lines
            var stripped = Regex.Replace(payload, @"^[\r\n]+", ""); // Remove leading CRLF characters at the very beginning

            // HTTP request line matcher pattern: \b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP/([0-9.]+)
            // \b                     : Word boundary so method starts at a boundary (avoids matching within a longer token)
            // (GET|POST|...|CONNECT) : Capturing group #1 enumerating allowed HTTP methods
            // \s+                    : One or more whitespace characters between method and path
            // (\S+)                  : Capturing group #2 for the request target/path (one or more non-whitespace chars)
            // \s+                    : One or more whitespace characters before protocol version
            // HTTP/                   : Literal "HTTP/"
            // ([0-9.]+)              : Capturing group #3 for version (digits and dots, e.g., 1.1)
            var reqMatch = Regex.Match(stripped, @"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP/([0-9.]+)", RegexOptions.IgnoreCase);
            if (reqMatch.Success)
                return $"HTTP Request ({reqMatch.Groups[1].Value} {reqMatch.Groups[2].Value} HTTP/{reqMatch.Groups[3].Value})";

            // HTTP response status line pattern: HTTP/([0-9.]+)\s+(\d{3})\s+([^\r\n]+)
            // HTTP/         : Literal protocol prefix
            // ([0-9.]+)     : Capturing group #1 version (digits and dots)
            // \s+           : One or more whitespace
            // (\d{3})       : Capturing group #2 exactly 3 digits (status code)
            // \s+           : One or more whitespace
            // ([^\r\n]+)   : Capturing group #3 reason phrase (any chars up to first CR or LF)
            var respMatch = Regex.Match(stripped, @"HTTP/([0-9.]+)\s+(\d{3})\s+([^\r\n]+)", RegexOptions.IgnoreCase);
            if (respMatch.Success)
                return $"HTTP Response (HTTP/{respMatch.Groups[1].Value} {respMatch.Groups[2].Value} {respMatch.Groups[3].Value.Trim()})";

            // Header presence heuristic pattern: (?mi)^(Host|User-Agent|Content-Type):
            // (?mi)            : Inline flags m = multi-line (^ and $ match line boundaries), i = case-insensitive
            // ^                : Start of a line (due to multiline)
            // (Host|User-Agent|Content-Type) : Capturing group of header names we care about
            // :                : Literal colon ending the header name
            if (payload.Contains("HTTP/") || Regex.IsMatch(payload, @"(?mi)^(Host|User-Agent|Content-Type):"))
                return "HTTP (partial)";

            return null;
        }

        /// <summary>
        /// Extracts a summary of the packet payload for display and logging.
        /// </summary>
        /// <param name="protocolLabel">The protocol label of the packet.</param>
        /// <param name="decodedPayload">The decoded packet payload.</param>
        /// <returns>A string summarizing the packet data.</returns>
        private string GetInformationPackage(string protocolLabel, string decodedPayload)
        {
            if (string.IsNullOrEmpty(decodedPayload)) return "No payload";

            // HTTP Request same pattern explanation as above in DetectHttpLabel
            // Pattern: \b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP/([0-9.]+)
            var reqMatch = Regex.Match(decodedPayload, @"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP/([0-9.]+)", RegexOptions.IgnoreCase);
            if (reqMatch.Success)
            {
                string method = reqMatch.Groups[1].Value;
                string path = reqMatch.Groups[2].Value;
                string version = reqMatch.Groups[3].Value;
                // Host header pattern: (?mi)^\s*Host:\s*(.+)$
                // (?mi)      : m = multiline (^/$ per line), i = ignore case
                // ^          : Start of line
                // \s*        : Optional leading whitespace before 'Host'
                // Host:       : Literal header name + colon
                // \s*        : Optional whitespace after colon
                // (.+)        : Capturing group #1 greedy – the remainder of the line (host value)
                // $          : End of line (multiline context)
                var hostMatch = Regex.Match(decodedPayload, @"(?mi)^\s*Host:\s*(.+)$");
                string hostFragment = hostMatch.Success ? $" Host:{hostMatch.Groups[1].Value.Trim()}" : "";
                return $"{method} {path} HTTP/{version}{hostFragment}";
            }

            // HTTP Response pattern same as in DetectHttpLabel: HTTP/([0-9.]+)\s+(\d{3})\s+([^\r\n]+)
            var respMatch = Regex.Match(decodedPayload, @"HTTP/([0-9.]+)\s+(\d{3})\s+([^\r\n]+)", RegexOptions.IgnoreCase);
            if (respMatch.Success)
            {
                string version = respMatch.Groups[1].Value;
                string status = respMatch.Groups[2].Value;
                string reason = respMatch.Groups[3].Value.Trim();
                return $"HTTP/{version} {status} {reason}";
            }

            // First non-empty line pattern: (?m)^[^\r\n]+
            // (?m)       : Multiline so ^ matches start of any line
            // ^          : Start of a line
            // [^\r\n]+  : One or more characters that are not CR or LF (captures an entire line until newline)
            var firstLineMatch = Regex.Match(decodedPayload, @"(?m)^[^\r\n]+");
            if (firstLineMatch.Success)
            {
                string firstLine = firstLineMatch.Value.Trim();
                if (firstLine.Length > 200) firstLine = firstLine.Substring(0, 200) + " ... (truncated)";
                return firstLine.Replace("\n", " ").Replace("\r", " ").Replace("\t", " ");
            }

            // Hex preview fallback
            try
            {
                string hexPreview = BitConverter.ToString(Encoding.UTF8.GetBytes(decodedPayload)).Replace("-", "").Substring(0, Math.Min(64, decodedPayload.Length * 2));
                return $"hex:{hexPreview}...";
            }
            catch
            {
                return "Non-text payload";
            }
        }

        /// <summary>
        /// Checks if a line starts with an HTTP method.
        /// </summary>
        /// <param name="line">The line to check.</param>
        /// <returns>True if the line starts with an HTTP method, false otherwise.</returns>
        private bool IsHttpMethodLine(string line)
        {
            if (string.IsNullOrEmpty(line)) return false;
            
            return line.StartsWith("GET", StringComparison.OrdinalIgnoreCase) ||
                   line.StartsWith("POST", StringComparison.OrdinalIgnoreCase) ||
                   line.StartsWith("PUT", StringComparison.OrdinalIgnoreCase) ||
                   line.StartsWith("DELETE", StringComparison.OrdinalIgnoreCase) ||
                   line.StartsWith("HEAD", StringComparison.OrdinalIgnoreCase) ||
                   line.StartsWith("OPTIONS", StringComparison.OrdinalIgnoreCase) ||
                   line.StartsWith("PATCH", StringComparison.OrdinalIgnoreCase) ||
                   line.StartsWith("CONNECT", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Extracts TCP flags from a TCP packet.
        /// </summary>
        /// <param name="tcp">The TCP packet.</param>
        /// <returns>A comma-separated string of TCP flags, or null if no flags are set.</returns>
        private string ExtractTcpFlags(TcpPacket tcp)
        {
            if (tcp == null) return null;

            var flags = new List<string>();
            if (tcp.Fin) flags.Add("FIN");
            if (tcp.Syn) flags.Add("SYN");
            if (tcp.Rst) flags.Add("RST");
            if (tcp.Psh) flags.Add("PSH");
            if (tcp.Ack) flags.Add("ACK");
            if (tcp.Urg) flags.Add("URG");

            return flags.Count > 0 ? string.Join(", ", flags) : null;
        }

        /// <summary>
        /// Extracts HTTP request URI from the decoded payload.
        /// </summary>
        /// <param name="decodedPayload">The decoded packet payload.</param>
        /// <returns>The HTTP request URI or null if not found.</returns>
        private string ExtractHttpRequestUri(string decodedPayload)
        {
            if (string.IsNullOrEmpty(decodedPayload)) return null;

            var reqMatch = HttpRequestRegex.Match(decodedPayload);
            if (reqMatch.Success)
            {
                return reqMatch.Groups[2].Value;
            }

            return null;
        }

        /// <summary>
        /// Extracts HTTP headers from the decoded payload.
        /// </summary>
        /// <param name="decodedPayload">The decoded packet payload.</param>
        /// <returns>A formatted string of HTTP headers or null if not found.</returns>
        private string ExtractHttpHeaders(string decodedPayload)
        {
            if (string.IsNullOrEmpty(decodedPayload)) return null;

            // Check if this is an HTTP request or response
            var isHttp = decodedPayload.Contains("HTTP/");

            if (!isHttp) return null;

            // Extract headers (lines after the request/response line until the first empty line)
            var lines = decodedPayload.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            var headers = new List<string>();
            bool inHeaders = false;

            foreach (var line in lines)
            {
                if (!inHeaders)
                {
                    // First line is the request/response line, skip it
                    if (IsHttpMethodLine(line) || line.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                    {
                        inHeaders = true;
                        continue;
                    }
                }
                else
                {
                    // Empty line marks end of headers
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        break;
                    }

                    // Check if line contains a colon (header format)
                    if (line.Contains(":"))
                    {
                        headers.Add(line.Trim());
                    }
                }
            }

            if (headers.Count > 0)
            {
                // Limit to first few headers to avoid cluttering the UI
                var result = string.Join("; ", headers.Take(5));
                if (headers.Count > 5)
                {
                    result += "...";
                }
                return result;
            }

            return null;
        }

        /// <summary>
        /// Processes a captured packet, updating the UI and logs.
        /// </summary>
        /// <param name="srcIp">Source IP address.</param>
        /// <param name="srcPort">Source port.</param>
        /// <param name="dstIp">Destination IP address.</param>
        /// <param name="dstPort">Destination port.</param>
        /// <param name="decodedPayload">Decoded packet payload.</param>
        /// <param name="protocolLabel">Protocol label.</param>
        /// <param name="packet">The parsed packet object.</param>
        /// <param name="tcpPacket">The TCP packet (if available).</param>
        private void ProcessPacket(string srcIp, int srcPort, string dstIp, int dstPort, string decodedPayload, string protocolLabel, PacketDotNet.Packet packet, TcpPacket tcpPacket = null)
        {
            string infoPkg = GetInformationPackage(protocolLabel, decodedPayload);
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string source = $"{srcIp}:{srcPort}";
            string destination = $"{dstIp}:{dstPort}";
            string simpleLine = $"[{timestamp}]: [{protocolLabel}] detected from [{source}] to [{destination}]: {infoPkg}";

            // Determine short protocol for filtering
            string shortProtocol = "Unknown";
            if (!string.IsNullOrEmpty(protocolLabel))
            {
                if (protocolLabel.StartsWith("HTTP", StringComparison.OrdinalIgnoreCase))
                    shortProtocol = "HTTP";
                else if (protocolLabel.StartsWith("TCP", StringComparison.OrdinalIgnoreCase))
                    shortProtocol = "TCP";
                else if (protocolLabel.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
                    shortProtocol = "UDP";
                else
                {
                    // fallback: try contains
                    if (protocolLabel.IndexOf("tcp", StringComparison.OrdinalIgnoreCase) >= 0) shortProtocol = "TCP";
                    else if (protocolLabel.IndexOf("udp", StringComparison.OrdinalIgnoreCase) >= 0) shortProtocol = "UDP";
                    else if (protocolLabel.IndexOf("http", StringComparison.OrdinalIgnoreCase) >= 0) shortProtocol = "HTTP";
                    else shortProtocol = protocolLabel;
                }
            }

            bool hasPayload = !string.IsNullOrEmpty(decodedPayload);

            // Extract TCP flags
            string tcpFlags = ExtractTcpFlags(tcpPacket);

            // Extract HTTP request URI and headers
            string httpRequestUri = ExtractHttpRequestUri(decodedPayload);
            string httpHeaders = ExtractHttpHeaders(decodedPayload);

            // Add to DataGrid (UI thread)
            Dispatcher.Invoke(() =>
            {
                _packets.Add(new PacketInfo
                {
                    Timestamp = timestamp,
                    Type = protocolLabel,
                    Protocol = shortProtocol,
                    Source = source,
                    Destination = destination,
                    CapturedData = infoPkg,
                    HasPayload = hasPayload,
                    TcpFlags = tcpFlags,
                    HttpRequestUri = httpRequestUri,
                    HttpHeaders = httpHeaders
                });

                // Apply filter refresh immediately so UI updates filtered list promptly
                _packetsView?.Refresh();
            });

            // Log to simple file
            _simpleLogWriter.WriteLine(simpleLine);
            _simpleLogWriter.Flush();

            // Log full payload
            string fullHeader = $"[{timestamp}] {protocolLabel} {source} -> {destination}";
            _fullPayloadWriter.WriteLine(fullHeader);
            _fullPayloadWriter.WriteLine(decodedPayload ?? "None");
            _fullPayloadWriter.WriteLine(new string('-', 80));
            _fullPayloadWriter.Flush();

            // Debug mode: Log preview to console (or add to UI if desired)
            if (_debugMode)
            {
                string preview = decodedPayload ?? "None";
                if (preview.Length > 1000) preview = preview.Substring(0, 1000) + " ... (truncated)";
                Console.WriteLine($"DEBUG preview: {preview}");
            }
        }
    }
}