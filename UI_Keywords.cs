namespace PacketSnifferWPF
{
    /// <summary>
    /// Contains all UI-related string constants used throughout the application.
    /// </summary>
    public static class UI_Keywords
    {
        // Window
        public const string WindowTitle = "Packet Sniffer";

        // Labels
        public const string InterfaceLabel = "Interface:";
        public const string PortsModeLabel = "Ports Mode:";
        public const string LogFileLabel = "Log File:";
        public const string ProtocolLabel = "Protocol:";
        public const string ConnectionStateLabel = "Connection State:";

        // Buttons
        public const string StartSniffingButton = "Start Sniffing";
        public const string StopSniffingButton = "Stop Sniffing";
        public const string ClearButton = "Clear";

        // CheckBoxes
        public const string DebugModeCheckBox = "Debug Mode";
        public const string OnlyWithPayloadCheckBox = "Only show packets with payload";

        // ComboBox Items
        public const string PortsModeAll = "all";
        public const string PortsModeCommon = "common";
        public const string PortsModeTargeted = "targeted";
        public const string PortsModeCustom = "custom";

        public const string ProtocolFilterAll = "All";
        public const string ProtocolFilterTCP = "TCP";
        public const string ProtocolFilterUDP = "UDP";
        public const string ProtocolFilterHTTP = "HTTP";

        // DataGrid Column Headers
        public const string TimestampColumn = "Timestamp";
        public const string TypeColumn = "Type";
        public const string ProtocolColumn = "Protocol";
        public const string SourceColumn = "Source";
        public const string DestinationColumn = "Destination";
        public const string TcpFlagsColumn = "TCP Flags";
        public const string ConnectionStateColumn = "Connection State";
        public const string HttpRequestUriColumn = "HTTP Request URI";
        public const string HttpHeadersColumn = "HTTP Headers";
        public const string HttpBodyColumn = "HTTP Body";
        public const string CapturedDataColumn = "Captured Data";

        // ToolTips
        public const string CustomPortsToolTip = "Enter comma-separated ports (e.g., 80,443)";

        // Messages
        public const string NoInterfacesMessage = "No interfaces found! Ensure Npcap is installed and run as admin.";
        public const string NoLoopbackMessage = "No loopback interface found! Ensure Npcap is installed with loopback support and run as admin.";
        public const string SelectInterfaceMessage = "Select an interface.";
        public const string EnterCustomPortsMessage = "Enter comma-separated ports for custom mode.";
        public const string InvalidPortsMessage = "Invalid ports: {0}";
        public const string FailedToOpenLogFilesMessage = "Failed to open log files: {0}";
        public const string FailedToOpenDeviceMessage = "Failed to open device: {0}: {1}";
        public const string FailedToStartCaptureMessage = "Failed to start capture: {0}";

        // Default Values
        public const string DefaultLogFile = "captured_packets_simple.txt";
        public const string FullPayloadLogFile = "captured_packets_full.txt";

        // Connection States
        public const string StateIdle = "Idle";
        public const string StateClientConnecting = "Client connecting to server (SYN)";
        public const string StateServerResponding = "Server responding (SYN-ACK)";
        public const string StateConnectionEstablished = "Connection established";
        public const string StateDataTransfer = "Data transfer in progress";
        public const string StateClientDisconnecting = "Client disconnecting (FIN)";
        public const string StateServerDisconnecting = "Server disconnecting (FIN)";
        public const string StateConnectionClosing = "Connection closing (FIN-ACK)";
        public const string StateConnectionReset = "Connection reset (RST) - Error occurred";
        public const string StateUnknown = "Unknown state";
    }
}
