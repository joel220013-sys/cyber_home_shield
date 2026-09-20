# Active ARP scan patch — where each file goes

Copy each file over the matching path in your project (same relative structure):

- backend/requirements.txt          -> adds scapy>=2.5.0
- backend/pyproject.toml            -> adds scapy>=2.5.0 to [project.dependencies]
- backend/app/config.py             -> adds ENABLE_ACTIVE_ARP_SCAN, ACTIVE_ARP_SCAN_TIMEOUT
- backend/app/services/discovery/arp_scanner.py     -> adds SafeHostDiscoverer.active_arp_scan()
- backend/app/services/discovery/network_provider.py -> wires active_arp_scan into discover()

## Install steps (Windows, your machine)

1. Activate your venv, then:
   pip install scapy

2. Install Npcap: https://npcap.com/#download
   During install, CHECK "Install Npcap in WinPcap API-compatible Mode"

3. Run the backend AS ADMINISTRATOR (right-click your terminal / IDE ->
   "Run as administrator"). Raw socket access for ARP requires it.
   If you don't run as admin, active_arp_scan() just returns {} silently
   and the app falls back to the existing passive discovery — nothing
   breaks, you just won't get the extra coverage.

4. Restart the backend, click "Discover Devices" again.

## What changed, conceptually

- New: SafeHostDiscoverer.active_arp_scan(subnet_cidr) sends real ARP
  "who-has" broadcasts and collects replies — this is what catches
  devices that ignore ICMP ping (client isolation, host firewalls),
  because ARP operates below any of that at Layer 2.
- network_provider.py now runs this alongside the existing passive
  ARP-table read, and treats a real ARP reply as its own reachability
  evidence ("active_arp_reply") — no separate ping needed for those
  hosts, since the ARP reply already proves the host is alive.
- Nothing about your existing safety model changed: still RFC1918-only,
  still no fabricated vendor/OS/hostname, still bounded by timeouts.
