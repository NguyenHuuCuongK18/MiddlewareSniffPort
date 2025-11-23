namespace MiddlewareTest
{
    /// <summary>
    /// Contains all logging-related string constants used throughout the application.
    /// </summary>
    public static class Logging_Keywords
    {
        // Log Format Patterns
        public const string TimestampFormat = "yyyy-MM-dd HH:mm:ss";
        public const string LogLineFormat = "[{0}]: [{1}] detected from [{2}] to [{3}]: {4}";
        public const string FullHeaderFormat = "[{0}] {1} {2} -> {3}";

        // Log Messages
        public const string SnifferAppliedFilter = "[Sniffer] Applied filter: {0}";
        public const string SnifferStartedCapture = "[Sniffer] Started capture on: {0}";
        public const string SnifferStoppedCapture = "[Sniffer] Stopped capture and closed device";
        public const string OpenDeviceError = "[Open device error] {0}: {1}";
        public const string FilterError = "[Filter error] {0}: {1} - continuing without filter";
        public const string StartCaptureError = "[StartCapture error] {0}: {1}";
        public const string StopCloseError = "[Stop/Close error] {0}: {1}";
        public const string HandlerError = "[Handler error {0}] {1}: {2}";

        // Log Separators
        public const string LogSeparator = "--------------------------------------------------------------------------------";
        public const int LogSeparatorLength = 80;

        // Truncation Messages
        public const string TruncatedSuffix = " ... (truncated)";
        public const string HexPrefix = "hex:";
        public const string HexSuffix = "...";

        // Debug Messages
        public const string DebugPreviewPrefix = "DEBUG preview: ";

        // Payload Display
        public const int MaxBodyDisplayLength = 500;
        public const int MaxDebugPreviewLength = 1000;
        public const int MaxFirstLineLength = 200;
        public const int MaxHexPreviewLength = 64;
    }
}
