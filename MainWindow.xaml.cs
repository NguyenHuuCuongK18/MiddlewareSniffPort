using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace PacketSnifferWPF
{
    public partial class MainWindow : Window
    {
        private ObservableCollection<PacketInfo> _packets = new ObservableCollection<PacketInfo>();
        private ICaptureDevice _device;
        private List<int> _monitoredPorts;
        private bool _debugMode;
        private StreamWriter _simpleLogWriter;
        private StreamWriter _fullPayloadWriter;
        private CancellationTokenSource _cancellationTokenSource;
        private bool _monitorAllPorts;

        public MainWindow()
        {
            InitializeComponent();
            PacketsDataGrid.ItemsSource = _packets;
            LoadInterfaces();
        }

        private void LoadInterfaces()
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count == 0)
            {
                MessageBox.Show("No interfaces found! Ensure Npcap is installed and run as admin.");
                return;
            }

            InterfaceComboBox.ItemsSource = devices.Select(d => d.Description).ToList();
            // Default to loopback if available
            var loopbackIndex = devices.ToList().FindIndex(d => d.Description.Contains("Loopback") || d.Name.Contains("lo"));
            InterfaceComboBox.SelectedIndex = loopbackIndex >= 0 ? loopbackIndex : 0;
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            if (InterfaceComboBox.SelectedItem == null)
            {
                MessageBox.Show("Select an interface.");
                return;
            }

            // Parse ports
            try
            {
                (_monitoredPorts, _monitorAllPorts) = ParsePorts(PortsTextBox.Text);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Invalid ports: {ex.Message}");
                return;
            }

            _debugMode = DebugCheckBox.IsChecked ?? false;
            var selectedInterface = CaptureDeviceList.Instance[InterfaceComboBox.SelectedIndex];

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

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            _simpleLogWriter?.Close();
            _fullPayloadWriter?.Close();
            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
        }

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
                ProcessPacket(srcIp, srcPort, dstIp, dstPort, decodedPayload, protocolLabel, packet);
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


        private string DetectHttpLabel(string payload)
        {
            if (string.IsNullOrEmpty(payload)) return null;

            var stripped = Regex.Replace(payload, @"^[\r\n]+", ""); // Remove leading CRLF

            var reqMatch = Regex.Match(stripped, @"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP/([0-9.]+)", RegexOptions.IgnoreCase);
            if (reqMatch.Success)
                return $"HTTP Request ({reqMatch.Groups[1].Value} {reqMatch.Groups[2].Value} HTTP/{reqMatch.Groups[3].Value})";

            var respMatch = Regex.Match(stripped, @"HTTP/([0-9.]+)\s+(\d{3})\s+([^\r\n]+)", RegexOptions.IgnoreCase);
            if (respMatch.Success)
                return $"HTTP Response (HTTP/{respMatch.Groups[1].Value} {respMatch.Groups[2].Value} {respMatch.Groups[3].Value.Trim()})";

            if (payload.Contains("HTTP/") || Regex.IsMatch(payload, @"(?mi)^(Host|User-Agent|Content-Type):"))
                return "HTTP (partial)";

            return null;
        }

        private string GetInformationPackage(string protocolLabel, string decodedPayload)
        {
            if (string.IsNullOrEmpty(decodedPayload)) return "No payload";

            // HTTP Request
            var reqMatch = Regex.Match(decodedPayload, @"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+(\S+)\s+HTTP/([0-9.]+)", RegexOptions.IgnoreCase);
            if (reqMatch.Success)
            {
                string method = reqMatch.Groups[1].Value;
                string path = reqMatch.Groups[2].Value;
                string version = reqMatch.Groups[3].Value;
                var hostMatch = Regex.Match(decodedPayload, @"(?mi)^\s*Host:\s*(.+)$");
                string hostFragment = hostMatch.Success ? $" Host:{hostMatch.Groups[1].Value.Trim()}" : "";
                return $"{method} {path} HTTP/{version}{hostFragment}";
            }

            // HTTP Response
            var respMatch = Regex.Match(decodedPayload, @"HTTP/([0-9.]+)\s+(\d{3})\s+([^\r\n]+)", RegexOptions.IgnoreCase);
            if (respMatch.Success)
            {
                string version = respMatch.Groups[1].Value;
                string status = respMatch.Groups[2].Value;
                string reason = respMatch.Groups[3].Value.Trim();
                return $"HTTP/{version} {status} {reason}";
            }

            // Fallback: First non-empty line or hex
            var firstLineMatch = Regex.Match(decodedPayload, @"(?m)^[^\r\n]+");
            if (firstLineMatch.Success)
            {
                string firstLine = firstLineMatch.Value.Trim();
                if (firstLine.Length > 200) firstLine = firstLine.Substring(0, 200) + " ... (truncated)";
                return firstLine.Replace("\n", " ").Replace("\r", " ").Replace("\t", " ");
            }

            // Hex preview
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

        private void ProcessPacket(string srcIp, int srcPort, string dstIp, int dstPort, string decodedPayload, string protocolLabel, PacketDotNet.Packet packet)
        {
            string infoPkg = GetInformationPackage(protocolLabel, decodedPayload);
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string source = $"{srcIp}:{srcPort}";
            string destination = $"{dstIp}:{dstPort}";
            string simpleLine = $"[{timestamp}]: [{protocolLabel}] detected from [{source}] to [{destination}]: {infoPkg}";

            // Add to DataGrid (UI thread)
            Dispatcher.Invoke(() =>
            {
                _packets.Add(new PacketInfo
                {
                    Timestamp = timestamp,
                    Type = protocolLabel,
                    Source = source,
                    Destination = destination,
                    CapturedData = infoPkg
                });
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