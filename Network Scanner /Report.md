# Network Scan Report

**Date:** 2026-06-08  
**Tool:** Nmap 7.95  
**Target:** 172.17.19.0/24  


## Summary

Scanned 256 IP addresses. Found 19 live hosts, 8 with open ports.
One critical misconfiguration was identified (exposed MySQL database).


## Hosts discovered

| IP Address | Open Ports | Device type (guessed) |
|------------|------------|-----------------------|
| 172.17.19.2 | 22, 80, 443 | University server |
| 172.17.19.3 | 22, 80, 443 | University server |
| 172.17.19.4 | 22, 80, 443, 16113 | Server (unknown service on 16113) |
| 172.17.19.6 | 22, 80, 443 | University server |
| 172.17.19.8 | 22, 80, 443 | University server |
| 172.17.19.10 | 80, 443 | Firewalled host |
| 172.17.19.15 | 22, 53, 443 | DNS server |
| 172.17.19.16 | 22, 80, 443 | Server with firewall |
| 172.17.19.26 | 22, 80, 111, 443 | File-sharing server (NFS) |
| 172.17.19.36 | 22, 80, 3306 | **CRITICAL — exposed database** |
| 172.17.19.49 | none | My own machine (Parrot OS) |
| 172.17.19.80 | 80, 631 | Network printer |
| 172.17.19.106 | 15 filtered ports | Heavily protected server |
| 172.17.19.131 | 5000, 7000, 9009 | Unknown device (unusual ports) |


## Critical finding

**Host:** 172.17.19.36  
**Port:** 3306 (MySQL)  
**Risk:** Critical

Port 3306 is the default MySQL database port. Having it open on a shared
network means any device on this subnet could attempt to connect directly
to the database without going through a web application layer. An attacker
could try default credentials (root with no password) or brute-force access.
If successful, they could read, modify, or delete all data in the database.

**Recommendation:** The MySQL service should be bound to localhost only
(127.0.0.1) and never exposed on a network interface. A firewall rule should
block port 3306 from all external connections.


## Other notable findings

| Host | Port | Service | Notes |
|------|------|---------|-------|
| 172.17.19.15 | 53 | DNS | DNS server for the network — normal |
| 172.17.19.26 | 111 | rpcbind | NFS file sharing exposed — should be firewalled |
| 172.17.19.80 | 631 | IPP | Network printer — normal |
| 172.17.19.106 | 5902 | VNC | Remote desktop — filtered but present |
| 172.17.19.131 | 5000, 7000, 9009 | Unknown | Unusual ports — needs investigation |



## What I learned

Running this scan showed me how much information is visible to anyone on a
shared network without any authentication. The most important finding was the
exposed MySQL port on .36 — in a real penetration test this would be
immediately escalated as a critical vulnerability. I also learned to
distinguish between "closed" ports (the service replied with RST — port
exists but nothing is listening) and "filtered" ports (a firewall is silently
dropping packets — more secure). The cluster of servers (.2, .3, .6, .8)
with identical port profiles suggests centrally managed university
infrastructure, possibly behind a load balancer.



## Tools used

- `nmap -sn 172.17.19.0/24` — host discovery
- `nmap 172.17.19.0/24 -oN ports.txt` — port scan with saved output

 ## Critical finding

**Host:** 172.17.19.36  
**Port:** 3306  
**Service:** MySQL (version scan returned "unauthorized")  
**OS:** Ubuntu Linux  
**Risk level:** Critical  

### What was found
Nmap successfully connected to port 3306 and received a response from MySQL,
confirming the database service is reachable from anywhere on the network.
The response "unauthorized" means MySQL is actively listening and rejected
the connection only because no credentials were supplied — not because of
a firewall.

The web server running on port 80 is nginx 1.18.0 (released 2020), which
is outdated. Current stable is 1.26.x. Outdated nginx versions may contain
known CVEs exploitable via crafted HTTP requests.

SSH is running OpenSSH 8.9p1 which is a current version. Risk is low
provided password authentication is disabled and only key-based login allowed.

### Why this is dangerous
Any machine on the 172.17.19.0/24 subnet can attempt to:
1. Connect directly to the MySQL database on port 3306
2. Try default credentials (root / empty password)
3. Run brute-force or credential-stuffing attacks
4. If successful — read, modify, or delete all database contents

### Recommendation
- Bind MySQL to localhost only: set `bind-address = 127.0.0.1` in `/etc/mysql/mysql.conf.d/mysqld.cnf`
- Add a firewall rule: `sudo ufw deny 3306`
- Upgrade nginx to current stable version (1.26.x)
- Verify SSH password authentication is disabled: `PasswordAuthentication no` in `/etc/ssh/sshd_config`
