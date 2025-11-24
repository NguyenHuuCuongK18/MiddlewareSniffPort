# Đề xuất đổi tên Header cho Bảng Log Giao tiếp Mạng (TCP/HTTP)

## Header Naming Recommendations for Network Packet Log Table

Dưới đây là các đề xuất đổi tên header trong bảng log giao tiếp mạng để phù hợp hơn với chuẩn lập trình TCP/HTTP:

---

## Bảng So Sánh Headers (Comparison Table)

| STT | Header Hiện Tại (Current) | Header Đề Xuất (Recommended) | Lý Do (Reasoning) |
|-----|---------------------------|------------------------------|-------------------|
| 1   | Timestamp                 | **Time** hoặc **Capture Time** | "Time" ngắn gọn và phổ biến trong các công cụ network như Wireshark, tcpdump. "Capture Time" cụ thể hơn. |
| 2   | Type                      | **Packet Type** hoặc **Info** | "Type" quá chung chung. "Packet Type" rõ ràng là loại gói tin. "Info" là tên phổ biến trong Wireshark để hiển thị thông tin tóm tắt. |
| 3   | Protocol                  | **Protocol** *(giữ nguyên)* | Header này đã hợp lý, Protocol là thuật ngữ chuẩn trong networking (TCP, UDP, HTTP, etc.). |
| 4   | Source                    | **Source Address** hoặc **Src** | Trong networking, "Source Address" hoặc viết tắt "Src" là chuẩn. Có thể thêm "Src IP:Port" để rõ ràng hơn. |
| 5   | Destination               | **Destination Address** hoặc **Dst** | Tương tự Source, "Destination Address" hoặc "Dst" là thuật ngữ chuẩn. "Dst IP:Port" cũng tốt. |
| 6   | TCP Flags                 | **Flags** hoặc **TCP Flags** *(giữ nguyên)* | Header này đã hợp lý với TCP programming. "Flags" ngắn gọn, "TCP Flags" rõ ràng hơn. |
| 7   | Connection State          | **State** hoặc **Conn State** | "Connection State" hơi dài. "State" hoặc "Conn State" ngắn gọn hơn và vẫn rõ nghĩa trong context networking. |
| 8   | HTTP Request URI          | **Request URI** hoặc **URI** | "HTTP Request URI" dài. "Request URI" hoặc đơn giản "URI" là đủ khi Protocol đã hiển thị HTTP. |
| 9   | HTTP Headers              | **Headers** hoặc **HTTP Headers** *(giữ nguyên)* | "Headers" ngắn gọn, "HTTP Headers" rõ ràng. Cả hai đều hợp lý. |
| 10  | HTTP Body                 | **Body** hoặc **Payload** | "HTTP Body" có thể rút gọn thành "Body" hoặc "Payload" (payload là thuật ngữ phổ biến cho dữ liệu trong gói tin). |
| 11  | Captured Data             | **Data** hoặc **Summary** | "Captured Data" dài. "Data" hoặc "Summary" ngắn gọn và rõ ràng (summary phù hợp vì nó là tóm tắt payload). |

---

## Đề Xuất Cụ Thể (Specific Recommendations)

### Phương Án 1: Theo Phong Cách Wireshark (Wireshark-Style)
Phong cách này được sử dụng rộng rãi trong các công cụ phân tích mạng chuyên nghiệp:

```
No. | Time            | Source          | Destination     | Protocol | Info                | Flags      | State
----|-----------------|-----------------|-----------------|----------|---------------------|------------|------------------
1   | 14:23:45.123    | 127.0.0.1:8000  | 127.0.0.1:50234 | TCP      | [SYN] Seq=0         | SYN        | Connecting
2   | 14:23:45.125    | 127.0.0.1:50234 | 127.0.0.1:8000  | TCP      | [SYN, ACK] Seq=0... | SYN,ACK    | Responding
3   | 14:23:45.126    | 127.0.0.1:8000  | 127.0.0.1:50234 | HTTP     | GET /api/users      | PSH,ACK    | Data Transfer
```

**Headers:**
- Time
- Source
- Destination  
- Protocol
- Info (thay cho "Type" và "Captured Data")
- Flags (thay cho "TCP Flags")
- State (thay cho "Connection State")

Các cột HTTP có thể ẩn/hiện tùy theo filter:
- Request URI (chỉ hiện khi có HTTP request)
- Headers (chỉ hiện khi có HTTP)
- Body (chỉ hiện khi có HTTP)

---

### Phương Án 2: Theo Phong Cách Tcpdump (Tcpdump-Style)
Phong cách command-line, ngắn gọn và technical:

```
Time            | Src             | Dst             | Proto | Flags  | Len | Summary
----------------|-----------------|-----------------|-------|--------|-----|--------------------
14:23:45.123456 | 127.0.0.1:8000  | 127.0.0.1:50234 | TCP   | S      | 60  | SYN
14:23:45.125678 | 127.0.0.1:50234 | 127.0.0.1:8000  | TCP   | SA     | 60  | SYN-ACK
14:23:45.126789 | 127.0.0.1:8000  | 127.0.0.1:50234 | HTTP  | PA     | 512 | GET /api/users
```

**Headers:**
- Time
- Src (thay cho "Source")
- Dst (thay cho "Destination")
- Proto (thay cho "Protocol")
- Flags
- Len (Length - có thể thêm)
- Summary (thay cho "Captured Data")

---

### Phương Án 3: Hybrid (Cân Bằng - Recommended)
Kết hợp giữa rõ ràng và ngắn gọn, phù hợp với UI/UX:

```
Capture Time    | Source Address  | Dest Address    | Protocol | Packet Info         | TCP Flags | Conn State
----------------|-----------------|-----------------|----------|---------------------|-----------|------------------
14:23:45.123    | 127.0.0.1:8000  | 127.0.0.1:50234 | TCP      | SYN                 | SYN       | Connecting
14:23:45.125    | 127.0.0.1:50234 | 127.0.0.1:8000  | TCP      | SYN-ACK             | SYN,ACK   | Responding
14:23:45.126    | 127.0.0.1:8000  | 127.0.0.1:50234 | HTTP     | GET /api/users      | PSH,ACK   | Data Transfer
```

**Headers:**
- Capture Time (thay cho "Timestamp")
- Source Address (thay cho "Source")
- Dest Address (thay cho "Destination")
- Protocol *(giữ nguyên)*
- Packet Info (thay cho "Type")
- TCP Flags *(giữ nguyên)*
- Conn State (thay cho "Connection State")

Các cột HTTP:
- Request URI *(giữ nguyên hoặc rút gọn thành "URI")*
- HTTP Headers *(có thể rút gọn thành "Headers")*
- HTTP Body *(có thể rút gọn thành "Payload")*
- Data/Summary (thay cho "Captured Data")

---

## Giải Thích Chi Tiết (Detailed Explanations)

### 1. Time / Capture Time
- **Vì sao:** "Timestamp" là thuật ngữ kỹ thuật, nhưng "Time" hoặc "Capture Time" ngắn gọn và dễ hiểu hơn.
- **Chuẩn ngành:** Wireshark dùng "Time", tcpdump dùng timestamp format.

### 2. Source Address / Src
- **Vì sao:** "Source" có thể hiểu là nhiều thứ (source code, data source). "Source Address" hoặc "Src" rõ ràng đây là địa chỉ mạng.
- **Chuẩn ngành:** RFC và các công cụ mạng thường dùng "Source Address" hoặc "Src IP".

### 3. Destination Address / Dst
- **Vì sao:** Tương tự Source, "Destination Address" hoặc "Dst" là chuẩn trong networking.
- **Chuẩn ngành:** Các công cụ network analysis dùng "Destination" hoặc "Dst".

### 4. Info / Packet Info
- **Vì sao:** "Type" quá chung chung. "Info" là tên Wireshark dùng để hiển thị thông tin tóm tắt về gói tin.
- **Chuẩn ngành:** Wireshark dùng cột "Info" để hiện packet details summary.

### 5. Flags
- **Vì sao:** "TCP Flags" có thể rút gọn thành "Flags" khi context đã rõ (cột Protocol có TCP).
- **Chuẩn ngành:** Tcpdump hiển thị flags dạng [S], [SA], [F], [P] rất ngắn gọn.

### 6. State / Conn State
- **Vì sao:** "Connection State" hơi dài dòng. "State" hoặc "Conn State" ngắn gọn hơn.
- **Chuẩn ngành:** Các công cụ monitoring thường dùng "State" cho connection state.

### 7. Request URI / URI
- **Vì sao:** "HTTP Request URI" thừa từ "HTTP" khi cột Protocol đã có. "Request URI" hoặc "URI" là đủ.
- **Chuẩn ngành:** HTTP spec và các tools thường chỉ dùng "URI" hoặc "Request-URI".

### 8. Body / Payload
- **Vì sao:** "HTTP Body" có thể rút gọn. "Body" hoặc "Payload" đều là thuật ngữ chuẩn.
- **Chuẩn ngành:** HTTP spec dùng "message-body", network programming thường dùng "payload".

### 9. Data / Summary
- **Vì sao:** "Captured Data" hơi dài. "Data" hoặc "Summary" ngắn gọn và rõ nghĩa.
- **Chuẩn ngành:** Wireshark hiển thị tóm tắt trong cột "Info", nhưng "Data" hoặc "Summary" cũng phù hợp.

---

## Khuyến Nghị Cuối Cùng (Final Recommendation)

Tôi đề xuất sử dụng **Phương Án 3 (Hybrid)** với các header sau:

### Headers Chính (Main Headers):
1. **Time** - ngắn gọn, dễ hiểu
2. **Source** - giữ ngắn gọn nhưng vẫn rõ ràng  
3. **Destination** - tương tự Source
4. **Protocol** - giữ nguyên (chuẩn)
5. **Info** - thay "Type", theo chuẩn Wireshark
6. **Flags** - rút gọn từ "TCP Flags"
7. **State** - rút gọn từ "Connection State"

### Headers HTTP (khi applicable):
8. **URI** - rút gọn từ "HTTP Request URI"
9. **Headers** - rút gọn từ "HTTP Headers"
10. **Payload** - thay "HTTP Body"
11. **Data** - thay "Captured Data"

---

## Ví Dụ Áp Dụng (Example Application)

### Before (Hiện tại):
```xml
<DataGridTextColumn Header="Timestamp" Binding="{Binding Timestamp}" Width="150"/>
<DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="200"/>
<DataGridTextColumn Header="Protocol" Binding="{Binding Protocol}" Width="80"/>
<DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="150"/>
<DataGridTextColumn Header="Destination" Binding="{Binding Destination}" Width="150"/>
<DataGridTextColumn Header="TCP Flags" Binding="{Binding TcpFlags}" Width="120"/>
<DataGridTextColumn Header="Connection State" Binding="{Binding ConnectionState}" Width="200"/>
<DataGridTextColumn Header="HTTP Request URI" Binding="{Binding HttpRequestUri}" Width="200"/>
<DataGridTextColumn Header="HTTP Headers" Binding="{Binding HttpHeaders}" Width="200"/>
<DataGridTextColumn Header="HTTP Body" Binding="{Binding HttpBody}" Width="200"/>
<DataGridTextColumn Header="Captured Data" Binding="{Binding CapturedData}" Width="*"/>
```

### After (Đề xuất - Option 1: Wireshark Style):
```xml
<DataGridTextColumn Header="Time" Binding="{Binding Timestamp}" Width="150"/>
<DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="150"/>
<DataGridTextColumn Header="Destination" Binding="{Binding Destination}" Width="150"/>
<DataGridTextColumn Header="Protocol" Binding="{Binding Protocol}" Width="80"/>
<DataGridTextColumn Header="Info" Binding="{Binding Type}" Width="250"/>
<DataGridTextColumn Header="Flags" Binding="{Binding TcpFlags}" Width="100"/>
<DataGridTextColumn Header="State" Binding="{Binding ConnectionState}" Width="150"/>
<DataGridTextColumn Header="URI" Binding="{Binding HttpRequestUri}" Width="200"/>
<DataGridTextColumn Header="Headers" Binding="{Binding HttpHeaders}" Width="200"/>
<DataGridTextColumn Header="Payload" Binding="{Binding HttpBody}" Width="200"/>
<DataGridTextColumn Header="Data" Binding="{Binding CapturedData}" Width="*"/>
```

### After (Đề xuất - Option 2: More Descriptive):
```xml
<DataGridTextColumn Header="Capture Time" Binding="{Binding Timestamp}" Width="150"/>
<DataGridTextColumn Header="Source Address" Binding="{Binding Source}" Width="150"/>
<DataGridTextColumn Header="Dest Address" Binding="{Binding Destination}" Width="150"/>
<DataGridTextColumn Header="Protocol" Binding="{Binding Protocol}" Width="80"/>
<DataGridTextColumn Header="Packet Info" Binding="{Binding Type}" Width="250"/>
<DataGridTextColumn Header="TCP Flags" Binding="{Binding TcpFlags}" Width="100"/>
<DataGridTextColumn Header="Conn State" Binding="{Binding ConnectionState}" Width="150"/>
<DataGridTextColumn Header="Request URI" Binding="{Binding HttpRequestUri}" Width="200"/>
<DataGridTextColumn Header="HTTP Headers" Binding="{Binding HttpHeaders}" Width="200"/>
<DataGridTextColumn Header="HTTP Body" Binding="{Binding HttpBody}" Width="200"/>
<DataGridTextColumn Header="Summary" Binding="{Binding CapturedData}" Width="*"/>
```

---

## Kết Luận (Conclusion)

Các header được đề xuất trên:
- ✅ Phù hợp với chuẩn lập trình TCP/HTTP
- ✅ Ngắn gọn, dễ đọc trong UI
- ✅ Phù hợp với các công cụ network analysis phổ biến (Wireshark, tcpdump)
- ✅ Giữ nguyên ý nghĩa kỹ thuật
- ✅ Dễ hiểu cho cả người dùng kỹ thuật và không chuyên sâu

**Lựa chọn tốt nhất:** 
- Nếu muốn theo chuẩn công nghiệp: **Option 1 (Wireshark Style)**
- Nếu muốn cân bằng giữa rõ ràng và ngắn gọn: **Option 2 (More Descriptive)**

---

*Tài liệu này chỉ đưa ra đề xuất, không thực hiện sửa code.*
