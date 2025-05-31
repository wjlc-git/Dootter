# Dootter
Python script for basic async DDoS protection on Linux. It monitors IP connection rates, blocks IPs exceeding limits via iptables, unblocks them after cooldown, supports simulated or real traffic (tcpdump), logs actions, and handles graceful shutdown. Requires root and Python 3.7+.
