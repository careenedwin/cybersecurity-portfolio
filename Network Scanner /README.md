# Project 1 — Network Scanner with Nmap

A bash-based network scanning tool that uses Nmap to discover live
hosts, open ports, and running services on a local network.



## What this project does

Network scanning is the first phase of any penetration test or security
audit — called reconnaissance. Before an attacker (or a defender) can
assess a network's security posture, they need to know what is actually
on the network. This tool automates that discovery process using Nmap,
the industry standard network scanner used by security professionals worldwide.



## How it works

The tool runs three scanning phases in sequence:

### Phase 1 — Host discovery
Sends ICMP echo requests (pings) to every IP address in the target
range. Any device that responds is marked as "up". This tells us how
many devices are on the network without yet touching any ports.

```bash
nmap -sn 192.168.1.0/24
```

### Phase 2 — Port scanning
For each live host, attempts a TCP connection to the 1000 most common
ports. The response to each attempt reveals the port's state:

| State | Meaning |
|-------|---------|
| open | A service is actively listening on this port |
| closed | The port exists but nothing is listening |
| filtered | A firewall is silently blocking the probe |

```bash
nmap 192.168.1.0/24
```

### Phase 3 — Service and version detection
For every open port found, sends additional probes to identify exactly
what software is running and which version. This is critical because
outdated software versions often have known vulnerabilities (CVEs).

```bash
nmap -sV 192.168.1.0/24
```



## TCP SYN scan — how Nmap checks a port

Nmap uses a "half-open" TCP scan by default. It sends a SYN packet
and reads the response without completing the full handshake:

Open port   →  SYN sent → SYN-ACK received  (port is listening)
Closed port →  SYN sent → RST received       (nothing listening)
Filtered    →  SYN sent → no response        (firewall blocking)

This is faster and less detectable than a full TCP connection scan.


## What the results reveal

Every open port is a potential entry point. A security analyst reads
scan results by asking three questions about each finding:

1. **Should this port be open?** Some services have no reason to be
   network-accessible (e.g. a database on port 3306).
2. **Is the version up to date?** Outdated software has known CVEs
   that can be looked up and exploited.
3. **Is this expected for this device?** An office printer running SSH
   is unusual and worth investigating.

## Common ports and what they mean

| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH | Remote login — should use key auth only |
| 53 | DNS | Domain name resolution |
| 80 | HTTP | Unencrypted web server |
| 111 | rpcbind | NFS file sharing — should be firewalled |
| 443 | HTTPS | Encrypted web server |
| 631 | IPP | Internet Printing Protocol — likely a printer |
| 3306 | MySQL | Database — should never be publicly exposed |
| 5900+ | VNC | Remote desktop — high risk if unprotected |



## How to run it

**Requirements:** Nmap, Linux terminal (tested on Parrot OS)

```bash
# Install Nmap
sudo apt install nmap -y

# Clone the repo
git clone https://github.com/YOUR_USERNAME/cybersecurity-portfolio.git
cd cybersecurity-portfolio/01-network-scanner

# Run the scan script
chmod +x scan.sh
./scan.sh
```

Results are saved automatically to the `scan_results/` folder with
timestamps so you can compare scans over time.


## Files in this folder

| File | Description |
|------|-------------|
| `scan.sh` | Main bash script — runs all three scan phases |
| `report.md` | Security concepts and what I learned |
| `scan_results/` | Output files saved by the script |
| `screenshots/` | Terminal output screenshots |


## What I learned

- How TCP/IP communication works at the packet level
- The difference between open, closed, and filtered ports
- How version detection helps identify vulnerable software
- Why some ports are inherently riskier than others
- How to document findings in a structured security report



## Tools and concepts used

- Nmap 7.95
- TCP SYN scanning
- Service and version detection
- ICMP host discovery
- Network reconnaissance methodology

