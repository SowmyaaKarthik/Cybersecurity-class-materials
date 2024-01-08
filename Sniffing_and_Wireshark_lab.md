Network sniffing involves capturing and analyzing data packets as they traverse a network. Wireshark is a widely-used tool for network sniffing and packet analysis. Here are lab practicals for network sniffing using Wireshark:

# Lab 1: Basic Packet Capture
### Steps:
- Open Wireshark and select the network interface to capture traffic.
- Start capturing packets by clicking on the "Start" button.
- Observe the captured packets in real-time.
- Stop the capture after a certain period.
- Analyze the captured packets to identify protocols, source, and destination addresses.
```
sudo wireshark
```

# Lab 2: Filtered Packet Capture
### Steps:
- Use display filters to capture only HTTP traffic- GUI
```
http
```
- Command to capture only HTTP traffic:
```
sudo tshark -i <interface> -Y http
```

- Capture packets from a specific IP address- GUI
```
ip.addr == 192.168.1.1
```
- Command to capture packets from a specific IP address:
```
sudo tshark -i <interface> -f "host 192.168.1.1"
```

# Lab 3: Password Sniffing

### Steps:
- Capture traffic on a network with unencrypted communication.
- Look for protocols transmitting plaintext passwords (e.g., HTTP, FTP).
- Analyze packets to extract username/password pairs.
```
sudo tshark -i <interface>
```

# Lab 4: DNS Analysis

### Steps:
- Capture packets containing DNS requests and responses.
- Identify domain names being queried.
- Analyze DNS responses for IP addresses.
```
sudo tshark -i <interface> -Y dns
```

# Lab 5: HTTPS Decryption

### Steps:
- Set up Wireshark to decrypt HTTPS traffic (requires the server's private key).
- Capture HTTPS traffic.
- Observe decrypted content and analyze the secure communication.

```
sudo tshark -i <interface> -o "ssl.keylog_file:<path_to_key_file>"
```

# Lab 6: ARP Poisoning

### Steps:
- Use tools like Ettercap or ARPspoof to perform ARP poisoning.
- Capture packets and analyze the redirected traffic.

```
sudo ettercap -T -q -M arp:remote /<gateway_IP>/ /<target_IP>/
```

# Lab 7: VoIP Packet Capture

### Steps:
- Capture packets on a network with VoIP traffic.
- Identify SIP and RTP packets.
- Analyze VoIP signaling and media streams.

```
sudo tshark -i <interface> -Y sip or rtp
```

# Lab 8: Wireless Packet Capture

### Steps:
- Use Wireshark with a wireless adapter to capture wireless packets.
- Analyze the captured packets for wireless-specific protocols.

```
sudo tshark -i <wireless_interface>
```

> ### Please replace <interface> with your network interface (e.g., eth0) and <wireless_interface> with your wireless network interface (e.g., wlan0). Ensure that you have the necessary permissions to capture packets (use sudo).

> ##### Note: Wireshark is often used with a graphical user interface (wireshark command), but the tshark command allows for command-line packet analysis. Adjust the commands based on specific requirements and scenarios.





