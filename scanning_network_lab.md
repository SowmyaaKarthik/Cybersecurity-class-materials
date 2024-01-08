 Network scanning is a fundamental aspect of cybersecurity, aiding in the identification of live hosts, open ports, and services on a network. Here's a set of lab practicals for network scanning:

 # Lab 1: Basic Network Discovery

 ### Steps:
 - Use the ping command to identify live hosts in a specified IP range.
```
ping -c 4 192.168.1.1
```
- Use a network scanning tool like `nmap` to identify live hosts.
```
nmap -sP 192.168.1.0/24
```

# Lab 2: Port Scanning
### Steps:
- Perform a basic TCP port scan on a target host using nmap.
```
nmap -p 1-1000 192.168.1.1
```
- Conduct a more detailed TCP scan to determine service versions.
```
nmap -sV 192.168.1.1
```

# Lab 3: Operating System Detection
#### Use `nmap` to perform operating system detection.
```
nmap -O 192.168.1.1
```
# Lab 4: Banner Grabbing
#### Manually connect to a specific port using `telnet` or `netcat` to retrieve banners.

```
nc -v 192.168.1.1 80
```
# Lab 5: Scanning Specific Ports
#### Use `nmap` to scan specific ports on a target machine.
```
nmap -p 80,443,22 192.168.1.1
```

# Lab 6: Full Network Scan
#### Use nmap to conduct a full network scan.
```
nmap -p- -sV 192.168.1.1
```

# Lab 7: Stealthy Scanning
### Steps:
- Use the -sS flag with nmap for a SYN scan.
```
nmap -sS 192.168.1.1
```
- Use the -sN flag for a NULL scan.
```
nmap -sN 192.168.1.1
```

> Note: -Always ensure you have the necessary permissions before conducting network scanning activities.-Familiarize yourself with the options and flags of the tools used for network scanning.-Document and analyze the results of each scan for a better understanding of the network's security posture.
