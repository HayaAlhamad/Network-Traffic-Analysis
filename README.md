# Network Traffic Analysis Techniques

This repository documents a series of hands-on exercises in network traffic analysis. It includes examples of using tools like Wireshark, tcpdump, and Burp Suite to capture, filter, and interpret network communications. These methods are fundamental to network troubleshooting, incident response, and security monitoring.

Each technique is also examined from a defender's perspective, documenting how the activity would appear in IDS, firewall, and endpoint logs.

All work was performed in a sandboxed virtual environment I control.

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
*  *(See burp-suite-https-interception-1.png and burp-suite-https-interception-2.png )*

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

---

## From the Defender's Side

Capturing and reading traffic is useful for troubleshooting, but the same skills are required to defend :)

### DHCP and TCP Handshake Captures

Knowing what a normal DORA exchange and a normal three-way handshake look like matters because it gives me a baseline. Once I know what's normal, I can spot what isn't:

**What to look for:**
- A client sending repeated DHCP Discover messages with no Offer coming back, which can mean a rogue or overloaded DHCP server, or no server reachable at all
- An unexpected DHCP server responding (a second Offer from an IP that shouldn't be handing out leases) — a classic sign of a rogue DHCP server on the network
- TCP handshakes that never complete (SYN with no SYN-ACK, or SYN-ACK with no final ACK), which can indicate a SYN scan or a service that's down

**A rule to write:**
> If more than one DHCP server IP responds to DHCP Discover messages within a short window, raise a "possible rogue DHCP server" alert.

**How to respond:** Identify the unexpected DHCP server's switch port and MAC address, and isolate it. If it's not an authorized device, this is a priority incident, since a rogue DHCP server can redirect clients' default gateway and DNS, enabling man-in-the-middle attacks.

### Watching for Cleartext Credentials (HTTP Interception)

Capturing an HTTP GET request with a cookie header in plain text was the point of this exercise, but from the defender's side the real question is: should this traffic exist at all?

**What to look for:**
- Any HTTP (not HTTPS) traffic carrying `Cookie`, `Authorization`, or form fields that look like credentials
- Internal traffic to login pages or APIs that isn't encrypted
- A DLP or IDS rule matching cleartext password fields in HTTP POST bodies

**A rule to write:**
> Flag any HTTP (port 80) request containing a `Cookie`, `Authorization`, or `password=` pattern as a "cleartext credential exposure" finding, not just an alert — this is usually a misconfiguration to fix, not an attack.

**How I'd respond:** This is less about catching an attacker and more about catching a weak spot before someone else does. I'd report it as a finding: redirect the service to HTTPS, and check whether anyone else on the network (or outside it, if this touches a public segment) could have captured that traffic.

### HTTPS Interception (Burp Suite / MitM Proxy)

Setting up a proxy to decrypt HTTPS traffic requires the client to trust the proxy's CA certificate. That requirement is exactly the detection opportunity:

**What to look for:**
- An unexpected or self-signed CA certificate installed in a user's trust store, which TLS inspection tools or endpoint management software can flag
- Certificate warnings a user reports seeing and ignoring, since users clicking through TLS warnings is how real MitM attacks often succeed
- Unusual certificate chains for well-known domains, which I'd check by actively monitoring certificate transparency logs or TLS fingerprints (e.g. JA3) for mismatches against expected values

**How to respond:** If this shows up unexpectedly on an endpoint (not as part of sanctioned corporate TLS inspection), I'd treat it as a strong indicator of an adversary-in-the-middle setup and isolate the host for investigation.

### What to take from this

The common thread across all three exercises is that each attack technique has a "normal baseline" it has to deviate from to work. A rogue DHCP server has to answer queries it shouldn't. Cleartext traffic has to not be encrypted. A MitM proxy has to install a cert it shouldn't be trusted to install. Knowing the protocols well enough to build these captures is the same knowledge needed to recognize when they look wrong.
