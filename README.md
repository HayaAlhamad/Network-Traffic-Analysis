# Network Traffic Analysis Techniques

This repository documents a series of hands-on exercises in network traffic analysis. It includes examples of using tools like Wireshark, tcpdump, and Burp Suite to capture, filter, and interpret network communications. These methods are fundamental to network troubleshooting, incident response, and security monitoring.

All work was performed in a sandboxed virtual environment.

---

## Protocol Handshake Analysis (Wireshark)

### Objective
To capture and visually identify the packets involved in fundamental network setup protocols: DHCP and TCP.

### Method
Wireshark was used to capture network traffic during two key operations:
1.  **DHCP Session:** The capture shows the four-step DORA (Discover, Offer, Request, Acknowledge) process a client machine uses to obtain an IP address from a DHCP server.
2.  **TCP Handshake:** The capture shows the classic three-way handshake (`SYN`, `SYN-ACK`, `ACK`) that establishes a reliable connection between a client and a server.

### Evidence
The screenshots showing these captures are included in this repository.
*   *(See `dhcp-dora-capture.png`)*
*   *(See `tcp-handshake-capture.png`)*

---

## HTTP Traffic Interception & Analysis

### Objective
To demonstrate the interception of unencrypted HTTP traffic to extract data (like cookies) and to explain the procedure for intercepting encrypted HTTPS traffic.

### Method
1.  **HTTP Interception:** `tcpdump` was used to capture traffic from a `curl` request to an unencrypted website. The output clearly shows the HTTP GET request and the `Cookie` header in plain text.
2.  **HTTPS Interception:** The process for intercepting HTTPS traffic was documented. This requires a proxy tool like **Burp Suite**, where the client is configured to trust the proxy's Certificate Authority (CA). This allows the proxy to perform a man-in-the-middle (MitM) decryption of the TLS traffic for inspection.

### Evidence
A screenshot of the Burp Suite configuration process is included in this repository.
*   *(See `burp-suite-https-interception.png` )*

---

## Advanced Filtering with `tcpdump`

### Objective
To construct and explain a complex `tcpdump` filter designed to isolate HTTP POST requests with data payloads.

### Method
The following `tcpdump` filter was analyzed. It works by calculating the TCP payload size and filtering for packets where the payload is not zero.

`'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'`

*   `ip[2:2]`: Fetches the total length of the IP packet.
*   `((ip[0]&0xf)<<2)`: Calculates the IP header length.
*   `((tcp[12]&0xf0)>>2)`: Calculates the TCP header length.

By subtracting the header lengths from the total length, we get the payload size. The `!= 0` ensures we only see packets that actually contain data, which is characteristic of a POST request.

### Evidence
A screenshot showing this `tcpdump` filter in action is included in this repository.
*   *(See `tcpdump-post-filter.png`)*
