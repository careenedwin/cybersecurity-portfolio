# Network Scanner — Project Report

**Tool:** Nmap 7.95

## Objective

To learn how network reconnaissance works by using Nmap to discover
devices and services on a local network, and to understand what
the results mean from a security perspective.


## How the tool works

### Host discovery

The first scan phase uses ICMP echo requests to find live devices.
Nmap sends a ping to every address in the target range and records
which ones respond. Devices that do not respond are either offline
or configured to ignore pings — the latter is itself a basic security
measure called ICMP filtering.

The response latency also provides useful information. Wired devices
typically respond in under 20ms. Wireless or mobile devices often
show 100ms or higher. Very high latency (300ms+) can indicate a
device that is partially asleep, heavily loaded, or located further
away on a routed network.

### Port scanning

Nmap scans the 1000 most commonly used TCP ports on each live host.
It uses a SYN scan — sending a TCP SYN packet and reading the response
without completing the handshake. This determines whether each port
is open, closed, or filtered by a firewall.

The distinction between closed and filtered is important from a
security perspective. A closed port tells an attacker the port number
is valid but nothing is listening. A filtered port reveals nothing
about what is behind it, making it harder to plan an attack.
Filtered ports are therefore more secure.

### Service and version detection

Once open ports are identified, Nmap sends targeted probes to each
one to identify the software running and its version number. It
matches responses against a database of known service signatures.

This phase is the most valuable for security assessment because
it turns a list of open ports into actionable intelligence. A port
number alone tells you what service is expected. The version number
tells you whether that service is up to date and whether known
vulnerabilities (CVEs) apply to it.


## Port risk analysis

### High-risk ports

**Port 3306 — MySQL**
A database port should never be accessible on a network interface.
MySQL should always be bound to localhost (`127.0.0.1`) so that
only applications running on the same machine can connect. When
exposed on a network, any device on the subnet can attempt to
connect and try credentials. Attackers typically try default
credentials first (root with no password) before attempting brute
force. A successful connection gives full access to all databases
on the server.

Correct fix: set `bind-address = 127.0.0.1` in the MySQL
configuration file and add a firewall rule blocking port 3306.

**Port 5900+ — VNC**
VNC provides full graphical remote desktop access. If not protected
by strong authentication and encryption, it allows complete control
of a machine remotely. VNC has a history of vulnerabilities and
should only ever be accessible via a VPN or SSH tunnel, never
directly on a network.

### Medium-risk ports

**Port 22 — SSH**
SSH is necessary for remote server management but is a constant
target for brute-force attacks. Best practice requires disabling
password authentication entirely and using key-based authentication
only. Port 22 should also be restricted to known IP addresses via
firewall rules where possible.

**Port 111 — rpcbind**
rpcbind is used by NFS (network file sharing). It has a history
of vulnerabilities and should be firewalled so it is not accessible
from outside the host that needs it. Exposed rpcbind on a shared
network is an unnecessary risk.

### Low-risk ports (in normal configurations)

**Port 80 / 443 — HTTP / HTTPS**
Web servers are expected to be publicly accessible. Port 80 serves
unencrypted traffic — modern web servers should redirect all HTTP
to HTTPS. Port 443 serves encrypted traffic and is generally safe
when the server software is kept up to date.

**Port 53 — DNS**
A DNS server on the network is expected and normal. Risk is low
unless the DNS server is misconfigured to allow zone transfers to
unauthorised clients, which could reveal the full list of hostnames
on a network.

**Port 631 — IPP**
Internet Printing Protocol identifies a network printer. The risk
is low but the web interface on port 80 of a printer should be
checked for default credentials, as many printers ship with no
password set.


## Defensive recommendations

Based on the port types commonly found during this exercise:

| Finding | Recommendation |
|---------|---------------|
| Database port exposed | Bind to localhost, block with firewall |
| Outdated web server | Upgrade to current stable version |
| SSH open | Disable password auth, use keys only |
| rpcbind exposed | Restrict with firewall rules |
| VNC accessible | Tunnel through SSH or restrict to VPN only |
| No HTTPS redirect | Force all HTTP traffic to HTTPS |

---

## Key concepts learned

**Reconnaissance is passive information gathering.**
No exploitation occurs during a scan. The value is in understanding
the attack surface — what is visible, what versions are running, and
what an attacker would see if they scanned the same network.

**Every open port is a potential entry point.**
This does not mean every open port is a vulnerability. It means every
open port deserves a justification. If a service is running on a port
and there is no clear reason for it to be there, it should be closed.

**Version information is critical.**
Knowing that a host runs nginx 1.18.0 allows a direct lookup of known
CVEs for that version. This turns a scan from a curiosity into an
actionable security assessment. Tools like `searchsploit` and the
National Vulnerability Database (NVD) can be queried with version
numbers to find exploits.

**Firewalls change what you see.**
A filtered port tells you more than a closed one — it tells you a
firewall is present and actively protecting that host. Analysing
which hosts are heavily filtered versus which have many open ports
reveals the network's security architecture.


## Tools used

```bash
nmap -sn TARGET/24        # Phase 1: host discovery
nmap TARGET/24            # Phase 2: port scan
nmap -sV TARGET/24        # Phase 3: version detection
sudo nmap -O TARGET/24    # Optional: OS detection
```

All output was saved using the `-oN` flag for documentation.


## References

- Nmap documentation — https://nmap.org/docs.html
- NIST National Vulnerability Database — https://nvd.nist.gov
- Common ports reference — IANA port assignments

