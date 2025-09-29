# PacketSnifferWPF

A Windows Presentation Foundation (WPF) application for capturing and analyzing network packets on loopback interfaces using Npcap. The application allows users to monitor TCP and UDP traffic, filter packets by protocol and payload, and log packet details to files.

- [ ] Table of Contents

- Features
- Prerequisites
- Installation
- Usage
- User Guide
- Project Structure
- Dependencies
- Troubleshooting
- License

## Features

- Capture TCP and UDP packets on loopback interfaces.
- Filter packets by:
  - Ports (all, common, targeted, or custom).
  - Protocol (All, TCP, UDP, HTTP).
  - Payload presence.
- Display packet details in a DataGrid, including timestamp, protocol, source, destination, and captured data.
- Log packet summaries to a simple log file and full payloads to a separate file.
- Debug mode for additional console output.
- Real-time packet filtering and display updates.

## Prerequisites

- **Operating System**: Windows (tested on Windows 10 and 11).
- **.NET Framework**: Version 4.8 or later.
- **Npcap**: Must be installed with loopback support enabled.
- **Administrative Privileges**: Required to capture packets.
- **Visual Studio**: Recommended for building and running the project (Community Edition is sufficient).

## Installation

1. **Install Npcap**:

   - Download and install Npcap from https://npcap.com.
   - During installation, ensure the "Support loopback traffic" option is checked.

2. **Clone the Repository**:

   ```bash
   git clone <repository-url>
   ```

3. **Open the Project**:

   - Open the solution (`PacketSnifferWPF.sln`) in Visual Studio.

4. **Install Dependencies**:

   - Restore NuGet packages for `PacketDotNet` and `SharpPcap`:

     ```bash
     Install-Package PacketDotNet
     Install-Package SharpPcap
     ```

5. **Build the Project**:

   - Build the solution in Visual Studio (Release or Debug mode).

6. **Run as Administrator**:

   - Ensure the application is run with administrative privileges to allow packet capturing.

## Usage

1. **Launch the Application**:
   - Run `PacketSnifferWPF.exe` as an administrator.
2. **Select an Interface**:
   - Choose a loopback interface from the dropdown (e.g., "Npcap Loopback Adapter").
3. **Configure Ports**:
   - Select a ports mode:
     - **All**: Capture all TCP/UDP ports.
     - **Common**: Capture ports 80, 443, 8000, 8080, 8888.
     - **Targeted**: Capture ports 5000, 8080.
     - **Custom**: Enter comma-separated ports (e.g., `80,443`).
4. **Set Log File**:
   - Specify the path for the simple log file (default: `captured_packets_simple.txt`).
   - Full payloads are logged to `captured_packets_full.txt` in the same directory.
5. **Enable Debug Mode (Optional)**:
   - Check the "Debug Mode" checkbox for additional console output.
6. **Apply Filters**:
   - Use the "Protocol" dropdown to filter by TCP, UDP, HTTP, or All.
   - Check "Only show packets with payload" to exclude packets without payload data.
7. **Start/Stop Sniffing**:
   - Click "Start Sniffing" to begin capturing packets.
   - Click "Stop Sniffing" to stop capturing and close log files.
8. **View Packets**:
   - Captured packets are displayed in the DataGrid with columns for Timestamp, Type, Protocol, Source, Destination, and Captured Data.
9. **Review Logs**:
   - Check `captured_packets_simple.txt` for packet summaries.
   - Check `captured_packets_full.txt` for full packet payloads.

## User Guide

### Interface Selection

- The application automatically lists loopback interfaces (e.g., Npcap Loopback Adapter).
- If no interfaces are listed, ensure Npcap is installed with loopback support and the application is run as administrator.

### Ports Mode

- **All**: Captures all TCP and UDP traffic, useful for broad monitoring.
- **Common**: Focuses on typical web-related ports (80, 443, 8000, 8080, 8888).
- **Targeted**: Monitors ports commonly used in development (5000, 8080).
- **Custom**: Allows specifying specific ports (e.g., `80,443,8080`).

### Filtering

- **Protocol Filter**: Select "TCP", "UDP", "HTTP", or "All" to filter displayed packets.
- **Payload Filter**: Enable "Only show packets with payload" to display only packets with non-empty payloads.
- Filters are applied in real-time as packets are captured.

### Logging

- **Simple Log** (`captured_packets_simple.txt`):

  - Contains packet summaries with timestamp, protocol, source, destination, and a brief data preview.
  - Example: `[2025-09-29 16:10:00]: [HTTP Request (GET /index.html HTTP/1.1)] detected from [127.0.0.1:12345] to [127.0.0.1:80]: GET /index.html HTTP/1.1 Host:localhost`

- **Full Payload Log** (`captured_packets_full.txt`):

  - Includes complete packet payloads with headers.

  - Example:

    ```
    [2025-09-29 16:10:00] HTTP Request (GET /index.html HTTP/1.1) 127.0.0.1:12345 -> 127.0.0.1:80
    GET /index.html HTTP/1.1
    Host: localhost
    User-Agent: Mozilla/5.0
    ...
    --------------------------------------------------------------------------------
    ```

### Debug Mode

- When enabled, packet payload previews are printed to the console (truncated to 1000 characters).
- Useful for developers to inspect raw packet data during troubleshooting.

### Stopping the Sniffer

- Click "Stop Sniffing" to halt packet capture and close log files.
- The application remains responsive, and you can start a new capture session.

## Project Structure

- **MainWindow.xaml**: Defines the UI layout with controls and DataGrid.
- **MainWindow.xaml.cs**: Contains the core logic for packet capturing, filtering, and logging.
- **PacketInfo.cs**: Data model for storing packet information displayed in the DataGrid.
- **app.manifest**: Configures the application to require administrative privileges.

## Dependencies

- **Npcap**: Packet capture library (requires installation with loopback support).
- **PacketDotNet**: NuGet package for parsing network packets.
- **SharpPcap**: NuGet package for interacting with Npcap to capture packets.
- **WPF**: Part of .NET Framework for the user interface.

## Troubleshooting

- **No Interfaces Listed**:
  - Ensure Npcap is installed with loopback support.
  - Run the application as an administrator.
  - Verify Npcap service is running (`sc query npcap` in Command Prompt).
- **Invalid Ports Error**:
  - For custom ports, ensure valid integers (1-65535) are entered, separated by commas (e.g., `80,443`).
- **Capture Fails to Start**:
  - Check if another application is using the Npcap driver.
  - Restart the Npcap service or reinstall Npcap.
- **No Packets Captured**:
  - Verify network traffic on the loopback interface (e.g., run a local web server or client).
  - Ensure the correct ports are monitored.
  - Disable filters to confirm packets are being captured.
- **Log Files Not Created**:
  - Ensure write permissions in the application’s directory.
  - Check the log file path in the UI for validity.

## License

This project is licensed under the MIT License. See the LICENSE file for details.