using System;

public class PacketInfo
{
	public PacketInfo()
	{
	}
    public string Timestamp { get; set; }
    public string Type { get; set; }           // original human-readable type (e.g., "HTTP Request (...)")
    public string Protocol { get; set; }       // short protocol: "TCP", "UDP", "HTTP", etc.
    public string Source { get; set; }
    public string Destination { get; set; }
    public string CapturedData { get; set; }   // info package / preview text
    public bool HasPayload { get; set; }       // true if a decoded payload exists (non-empty)
}