using MiddlewareTest;
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
        private IPacketCaptureService _packetCaptureService;
        private bool _debugMode;
        private StreamWriter? _simpleLogWriter;
        private StreamWriter? _fullPayloadWriter;
        private CancellationTokenSource? _cancellationTokenSource;

        // Lock object for thread-safe file writing
        private readonly object _fileLock = new object();

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

            // Initialize packet capture service
            _packetCaptureService = new PacketCaptureService();
            _packetCaptureService.PacketCaptured += OnPacketCaptured;
            _packetCaptureService.LogMessage += OnServiceLogMessage;

            // set items source and build collection view for filtering
            PacketsDataGrid.ItemsSource = _packets;
            _packetsView = CollectionViewSource.GetDefaultView(_packets);
            _packetsView.Filter = PacketFilter;

            // Initialize connection state label
            ConnectionStateLabel.Content = UI_Keywords.StateIdle;
            ConnectionStateLabel.Foreground = System.Windows.Media.Brushes.Gray;

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
        private void FilterControlChanged(object sender, RoutedEventArgs e)
        {
            _packetsView?.Refresh();
        }

        /// <summary>
        /// Handles changes to the protocol filter ComboBox, refreshing the packet view.
        /// </summary>
        private void FilterControlChanged(object sender, SelectionChangedEventArgs e)
        {
            _packetsView?.Refresh();
        }

        /// <summary>
        /// Filters packets for display based on protocol and payload settings.
        /// </summary>
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

            // Filter to only loopback interfaces
            var loopbackDevices = devices.Where(d =>
                d.Description.Contains("loopback", StringComparison.OrdinalIgnoreCase) ||
                d.Name.Contains("lo", StringComparison.OrdinalIgnoreCase)).ToList();

            if (loopbackDevices.Count == 0)
            {
                MessageBox.Show("No loopback interface found! Ensure Npcap is installed with loopback support and run as admin.");
                return;
            }

            InterfaceComboBox.ItemsSource = loopbackDevices.Select(d => d.Description).ToList();
            InterfaceComboBox.SelectedIndex = 0; // Default to the first loopback interface
        }

        /// <summary>
        /// Starts packet sniffing when the Start button is clicked.
        /// </summary>
        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            if (InterfaceComboBox.SelectedItem == null)
            {
                MessageBox.Show(UI_Keywords.SelectInterfaceMessage);
                return;
            }

            // Get ports arg from new controls
            string portsArg = PortsModeComboBox.SelectedItem?.ToString() ?? Service_Keywords.PortsModeTargeted;
            string? customPorts = null;

            if (portsArg == Service_Keywords.PortsModeCustom)
            {
                customPorts = CustomPortsTextBox.Text.Trim();
                if (string.IsNullOrEmpty(customPorts))
                {
                    MessageBox.Show(UI_Keywords.EnterCustomPortsMessage);
                    return;
                }
            }

            _debugMode = DebugCheckBox.IsChecked ?? false;
            var selectedIndex = InterfaceComboBox.SelectedIndex;
            var selectedInterface = CaptureDeviceList.Instance.Where(d =>
                d.Description.Contains(Validation_Keywords.LoopbackKeywordLower, StringComparison.OrdinalIgnoreCase) ||
                d.Name.Contains(Validation_Keywords.LoopbackInterfaceKeyword, StringComparison.OrdinalIgnoreCase)).ToList()[selectedIndex];

            // Open log files
            try
            {
                // Ensure directory exists if needed, mostly redundant as StreamWriter handles file creation usually
                _simpleLogWriter = new StreamWriter(LogFileTextBox.Text, true, Encoding.UTF8);
                _fullPayloadWriter = new StreamWriter(UI_Keywords.FullPayloadLogFile, true, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                MessageBox.Show(string.Format(UI_Keywords.FailedToOpenLogFilesMessage, ex.Message));
                return;
            }

            // Start sniffing on background thread using the service
            _cancellationTokenSource = new CancellationTokenSource();
            Task.Run(() => _packetCaptureService.StartCaptureAsync(selectedInterface, portsArg, customPorts, _cancellationTokenSource.Token));

            StartButton.IsEnabled = false;
            StopButton.IsEnabled = true;
        }

        /// <summary>
        /// Stops packet sniffing and closes log files when the Stop button is clicked.
        /// </summary>
        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            _packetCaptureService.StopCapture();

            lock (_fileLock)
            {
                _simpleLogWriter?.Close();
                _fullPayloadWriter?.Close();
                _simpleLogWriter = null;
                _fullPayloadWriter = null;
            }

            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
        }

        /// <summary>
        /// Clears all captured packets from the DataGrid when the Clear button is clicked.
        /// </summary>
        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            _packets.Clear();
            UpdateConnectionStateLabel(UI_Keywords.StateIdle);
        }

        /// <summary>
        /// Handles packet captured event from the service.
        /// </summary>
        private void OnPacketCaptured(object? sender, PacketCapturedEventArgs e)
        {
            // Normalize protocol label with HTTP detection
            string protocolLabel = e.ProtocolLabel;
            var httpLabel = DetectHttpLabel(e.DecodedPayload);
            if (!string.IsNullOrEmpty(httpLabel))
                protocolLabel = httpLabel;

            ProcessPacket(e.SourceIp, e.SourcePort, e.DestinationIp, e.DestinationPort,
                          e.DecodedPayload, protocolLabel, e.Packet, e.TcpPacket, e.RawPayloadData);
        }

        /// <summary>
        /// Handles log message events from the service.
        /// </summary>
        private void OnServiceLogMessage(object? sender, LogMessageEventArgs e)
        {
            // Log messages are infrequent, so basic locking is fine
            lock (_fileLock)
            {
                _simpleLogWriter?.WriteLine(e.Message);
                // We can flush service messages to ensure errors are seen immediately
                _simpleLogWriter?.Flush();
            }

            if (e.IsError)
            {
                Dispatcher.BeginInvoke(new Action(() => MessageBox.Show(e.Message)));
            }
        }

        // ... (DetectHttpLabel, GetInformationPackage, IsHttpMethodLine, ExtractTcpFlags, 
        //      ExtractHttpRequestUri, IsHttpPayload, ExtractHttpHeaders, ExtractHttpBody, 
        //      IsPureAck, TruncateString, DetermineConnectionState methods remain unchanged)

        /// <summary>
        /// Detects if the payload contains HTTP data and returns an appropriate label.
        /// </summary>
        private string? DetectHttpLabel(string? payload)
        {
            if (string.IsNullOrEmpty(payload)) return null;

            var stripped = Regex.Replace(payload, @"^[\r\n]+", "");

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

        private string GetInformationPackage(string protocolLabel, string? decodedPayload)
        {
            if (string.IsNullOrEmpty(decodedPayload)) return "No payload";

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

            var respMatch = Regex.Match(decodedPayload, @"HTTP/([0-9.]+)\s+(\d{3})\s+([^\r\n]+)", RegexOptions.IgnoreCase);
            if (respMatch.Success)
            {
                string version = respMatch.Groups[1].Value;
                string status = respMatch.Groups[2].Value;
                string reason = respMatch.Groups[3].Value.Trim();
                return $"HTTP/{version} {status} {reason}";
            }

            var firstLineMatch = Regex.Match(decodedPayload, @"(?m)^[^\r\n]+");
            if (firstLineMatch.Success)
            {
                string firstLine = firstLineMatch.Value.Trim();
                if (firstLine.Length > 200) firstLine = firstLine.Substring(0, 200) + " ... (truncated)";
                return firstLine.Replace("\n", " ").Replace("\r", " ").Replace("\t", " ");
            }

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

        private string? ExtractTcpFlags(TcpPacket? tcp)
        {
            if (tcp == null) return null;

            var flags = new List<string>();
            if (tcp.Finished) flags.Add(Network_Keywords.TcpFlagFIN);
            if (tcp.Synchronize) flags.Add(Network_Keywords.TcpFlagSYN);
            if (tcp.Reset) flags.Add(Network_Keywords.TcpFlagRST);
            if (tcp.Push) flags.Add(Network_Keywords.TcpFlagPSH);
            if (tcp.Acknowledgment) flags.Add(Network_Keywords.TcpFlagACK);
            if (tcp.Urgent) flags.Add(Network_Keywords.TcpFlagURG);
            if (tcp.ExplicitCongestionNotificationEcho) flags.Add(Network_Keywords.TcpFlagECE);
            if (tcp.CongestionWindowReduced) flags.Add(Network_Keywords.TcpFlagCWR);

            return flags.Count > 0 ? string.Join(", ", flags) : null;
        }

        private string? ExtractHttpRequestUri(string? decodedPayload)
        {
            if (string.IsNullOrEmpty(decodedPayload)) return null;

            var reqMatch = HttpRequestRegex.Match(decodedPayload);
            if (reqMatch.Success)
            {
                return reqMatch.Groups[2].Value;
            }

            return null;
        }

        private bool IsHttpPayload(string? decodedPayload)
        {
            if (string.IsNullOrEmpty(decodedPayload)) return false;
            return decodedPayload.Contains("HTTP/");
        }

        private string? ExtractHttpHeaders(string? decodedPayload)
        {
            if (!IsHttpPayload(decodedPayload)) return null;

            var lines = decodedPayload.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
            var headers = new List<string>();
            bool inHeaders = false;

            foreach (var line in lines)
            {
                if (!inHeaders)
                {
                    if (IsHttpMethodLine(line) || line.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                    {
                        inHeaders = true;
                        continue;
                    }
                }
                else
                {
                    if (string.IsNullOrWhiteSpace(line)) break;
                    if (line.Contains(":")) headers.Add(line.Trim());
                }
            }

            if (headers.Count > 0)
            {
                var result = string.Join("; ", headers.Take(5));
                if (headers.Count > 5) result += "...";
                return result;
            }

            return null;
        }

        private string? ExtractHttpBody(string? decodedPayload)
        {
            if (!IsHttpPayload(decodedPayload)) return null;

            int bodyStartIndex = -1;
            bodyStartIndex = decodedPayload.IndexOf("\r\n\r\n");
            if (bodyStartIndex != -1)
            {
                bodyStartIndex += 4;
            }
            else
            {
                bodyStartIndex = decodedPayload.IndexOf("\n\n");
                if (bodyStartIndex != -1) bodyStartIndex += 2;
            }

            if (bodyStartIndex != -1 && bodyStartIndex < decodedPayload.Length)
            {
                string body = decodedPayload.Substring(bodyStartIndex);
                if (!string.IsNullOrWhiteSpace(body))
                {
                    if (body.Length > Logging_Keywords.MaxBodyDisplayLength)
                    {
                        return TruncateString(body, Logging_Keywords.MaxBodyDisplayLength);
                    }
                    return body;
                }
            }

            return null;
        }

        private bool IsPureAck(TcpPacket? tcp)
        {
            return tcp != null && tcp.Acknowledgment && !tcp.Synchronize && !tcp.Finished && !tcp.Reset && !tcp.Push;
        }

        private string? TruncateString(string? text, int maxLength)
        {
            if (string.IsNullOrEmpty(text) || text.Length <= maxLength)
                return text;

            return text.Substring(0, maxLength) + Logging_Keywords.TruncatedSuffix;
        }

        private string? DetermineConnectionState(TcpPacket? tcp)
        {
            if (tcp == null) return null;

            if (tcp.Reset) return UI_Keywords.StateConnectionReset;

            if (tcp.Synchronize && tcp.Acknowledgment) return UI_Keywords.StateServerResponding;
            else if (tcp.Synchronize) return UI_Keywords.StateClientConnecting;

            if (tcp.Finished && tcp.Acknowledgment) return UI_Keywords.StateConnectionClosing;
            else if (tcp.Finished) return UI_Keywords.StateClientDisconnecting;

            if (tcp.Push && tcp.Acknowledgment) return UI_Keywords.StateDataTransfer;

            if (IsPureAck(tcp)) return UI_Keywords.StateConnectionEstablished;

            return null;
        }

        /// <summary>
        /// Updates the connection state label in the UI.
        /// </summary>
        private void UpdateConnectionStateLabel(string? state)
        {
            if (string.IsNullOrEmpty(state)) return;

            // Use BeginInvoke to prevent blocking
            Dispatcher.BeginInvoke(new Action(() =>
            {
                ConnectionStateLabel.Content = state;

                if (state == UI_Keywords.StateConnectionReset)
                    ConnectionStateLabel.Foreground = System.Windows.Media.Brushes.Red;
                else if (state == UI_Keywords.StateConnectionEstablished ||
                         state == UI_Keywords.StateDataTransfer)
                    ConnectionStateLabel.Foreground = System.Windows.Media.Brushes.Green;
                else if (state == UI_Keywords.StateClientDisconnecting ||
                         state == UI_Keywords.StateConnectionClosing)
                    ConnectionStateLabel.Foreground = System.Windows.Media.Brushes.Orange;
                else if (state == UI_Keywords.StateClientConnecting ||
                         state == UI_Keywords.StateServerResponding)
                    ConnectionStateLabel.Foreground = System.Windows.Media.Brushes.Blue;
                else
                    ConnectionStateLabel.Foreground = System.Windows.Media.Brushes.Gray;
            }));
        }

        /// <summary>
        /// Processes a captured packet, updating the UI and logs.
        /// Refactored to use BeginInvoke and Buffered I/O to avoid packet loss.
        /// </summary>
        private void ProcessPacket(string srcIp, int srcPort, string dstIp, int dstPort, string? decodedPayload, string protocolLabel, PacketDotNet.Packet packet, TcpPacket? tcpPacket = null, byte[]? rawPayloadData = null)
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
                    if (protocolLabel.IndexOf("tcp", StringComparison.OrdinalIgnoreCase) >= 0) shortProtocol = "TCP";
                    else if (protocolLabel.IndexOf("udp", StringComparison.OrdinalIgnoreCase) >= 0) shortProtocol = "UDP";
                    else if (protocolLabel.IndexOf("http", StringComparison.OrdinalIgnoreCase) >= 0) shortProtocol = "HTTP";
                    else shortProtocol = protocolLabel;
                }
            }

            bool hasPayload = !string.IsNullOrEmpty(decodedPayload);
            string tcpFlags = ExtractTcpFlags(tcpPacket);
            string connectionState = DetermineConnectionState(tcpPacket);

            if (!string.IsNullOrEmpty(connectionState))
            {
                UpdateConnectionStateLabel(connectionState);
            }

            string httpRequestUri = ExtractHttpRequestUri(decodedPayload);
            string httpHeaders = ExtractHttpHeaders(decodedPayload);
            string httpBody = ExtractHttpBody(decodedPayload);

            // Add to DataGrid (UI thread) - Asynchronous
            Dispatcher.BeginInvoke(new Action(() =>
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
                    ConnectionState = connectionState ?? "",
                    HttpRequestUri = httpRequestUri ?? "",
                    HttpHeaders = httpHeaders ?? "",
                    HttpBody = httpBody ?? ""
                });

                // Apply filter refresh
                _packetsView?.Refresh();
            }));

            // File logging inside lock, REMOVED FLUSH calls for performance
            lock (_fileLock)
            {
                if (_simpleLogWriter != null)
                {
                    _simpleLogWriter.WriteLine(simpleLine);
                }

                if (_fullPayloadWriter != null)
                {
                    string fullHeader = $"[{timestamp}] {protocolLabel} {source} -> {destination}";
                    _fullPayloadWriter.WriteLine(fullHeader);
                    _fullPayloadWriter.WriteLine(decodedPayload ?? "None");

                    if (rawPayloadData != null && rawPayloadData.Length > 0)
                    {
                        _fullPayloadWriter.WriteLine();
                        _fullPayloadWriter.WriteLine("Raw payload (hex):");
                        string hexString = string.Join(" ", rawPayloadData.Select(b => b.ToString("X2")));
                        _fullPayloadWriter.WriteLine(hexString);
                        _fullPayloadWriter.WriteLine();
                        _fullPayloadWriter.WriteLine($"Raw payload length: {rawPayloadData.Length} bytes");
                    }

                    _fullPayloadWriter.WriteLine(new string('-', Logging_Keywords.LogSeparatorLength));
                }
            }

            // Debug mode: Log preview to console
            if (_debugMode)
            {
                string preview = decodedPayload ?? "None";
                if (preview.Length > Logging_Keywords.MaxDebugPreviewLength)
                    preview = TruncateString(preview, Logging_Keywords.MaxDebugPreviewLength);
                Console.WriteLine($"DEBUG preview: {preview}");
            }
        }
    }
}