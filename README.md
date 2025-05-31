# Dootter

#Overview
This Python script provides a lightweight, asynchronous DDoS protection service designed for Linux servers. It monitors incoming IP connections in real time, tracks the rate of connection attempts per IP address, and automatically blocks IPs that exceed configurable thresholds using iptables. After a cooldown period, blocked IPs are unblocked automatically. The script supports simulated traffic for testing purposes and can be adapted to monitor live network traffic using tcpdump. This tool is ideal for small to medium Linux servers needing simple rate-limit-based protection from network abuse, brute force, or simple DDoS attempts. It also serves as a practical example of using Python’s asyncio for network monitoring and automating firewall rules.

#Features
- Asynchronous Monitoring: Utilizes Python’s asyncio to efficiently handle many IP connection events without blocking.
- Configurable Rate Limits: Set the maximum allowed connections per IP within a time window.
- Automatic Blocking/Unblocking: Adds and removes iptables rules to block abusive IPs temporarily.
- Simulated Traffic Generator: Built-in IP generator simulates normal and attacker traffic for testing.
- Real Network Monitoring: (Optional) Uses tcpdump to capture live TCP connections in real time.
- Graceful Shutdown: Captures termination signals to unblock all IPs before exit.
- Logging: Logs blocking and unblocking events, as well as errors, to a user-specified log file.
- Interactive Setup: Prompts user at startup for key parameters such as rate limit, interval, cooldown, and log file location.

# Requirements
- Linux operating system with iptables installed.
- Root or sudo privileges to modify firewall rules.
- Python 3.7 or higher (for asyncio subprocess support).
- (Optional) tcpdump installed if monitoring live traffic.

#Usage
- RATE_LIMIT: Maximum number of connections per IP allowed in the time window.
- INTERVAL: Time window in seconds for counting connections.
- COOLDOWN: Duration in seconds to keep an IP blocked before unblocking.
- LOG_FILE: File path for logging events.

Example inputs (press enter to accept defaults):

Enter maximum allowed connections per interval (RATE_LIMIT) [50]: 
Enter time window in seconds to count connections (INTERVAL) [60]: 
Enter cooldown time in seconds to block IPs (COOLDOWN) [300]: 

# Simulated Traffic
By default, the script runs with a simulated traffic generator that sends bursts of normal and attacker IPs to test blocking behavior. This allows you to verify that the script correctly blocks and unblocks IPs as expected.


# How It Works
The script asynchronously receives IP addresses from the chosen source.
For each IP, it tracks the timestamps of recent connection attempts.
If the number of connections within the configured interval exceeds the rate limit, it blocks the IP using iptables.
Blocked IPs remain blocked for the cooldown period, after which they are automatically unblocked.
All block/unblock actions and errors are logged to the specified log file.
On receiving termination signals (e.g., Ctrl+C), the script unblocks all IPs it blocked before exiting cleanly.

# Troubleshooting
Permission Denied Errors: Ensure you run the script with sudo or as root since modifying iptables requires elevated privileges.
iptables Not Found: Install iptables using your Linux distro’s package manager (e.g., apt install iptables).
Incorrect Network Interface: Update the interface name in read_real_ips() to match your system (eth0, ens33, etc.).
Parsing Errors with tcpdump: The script parses tcpdump output roughly; adjust parsing logic in read_real_ips() if needed for your tcpdump version or output format.

# Security Considerations
This script provides basic rate-limiting and blocking. It is not a replacement for full-featured firewalls or dedicated DDoS protection services.
Use with caution on production servers—test thoroughly.
Always keep backups of iptables rules and monitor logs.

Contribution
Contributions and improvements are welcome! Feel free to open issues or submit pull requests.

License
This project is licensed under the MIT License. See the LICENSE file for details.
