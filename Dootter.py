import asyncio
import subprocess
import time
import ipaddress
import logging
from collections import deque, defaultdict
import signal
import sys

# ----- Globals -----
connection_tracker = defaultdict(lambda: deque())  # IP -> deque[timestamps]
blocked_ips = {}  # IP -> block_time
running = True

def print_ascii_title():
    title = r"""
  ____              _   _             
 |  _ \  ___   ___ | |_| |_ ___  _ __ 
 | | | |/ _ \ / _ \| __| __/ _ \| '__|
 | |_| | (_) | (_) | |_| ||  __/| |   
 |____/ \___/ \___/ \__|\__\___||_|   
                                                                        
    """
    print(title)

def prompt_int(prompt_text, default):
    while True:
        try:
            value = input(f"{prompt_text} [{default}]: ").strip()
            if not value:
                return default
            ivalue = int(value)
            if ivalue <= 0:
                print("Please enter a positive integer.")
                continue
            return ivalue
        except ValueError:
            print("Invalid input, please enter an integer.")

def prompt_str(prompt_text, default):
    value = input(f"{prompt_text} [{default}]: ").strip()
    return value if value else default

# ----- Setup logging -----
def setup_logging(log_file):
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s"
    )

def is_valid_ip(ip: str) -> bool:
    """Validate IP address format."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


async def block_ip(ip: str):
    """Block IP via iptables."""
    if not is_valid_ip(ip):
        logging.warning(f"Invalid IP tried to block: {ip}")
        return
    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd)
        await proc.communicate()
        if proc.returncode == 0:
            blocked_ips[ip] = time.time()
            logging.info(f"Blocked IP: {ip}")
        else:
            logging.error(f"Failed to block IP: {ip} (return code {proc.returncode})")
    except Exception as e:
        logging.error(f"Exception blocking IP {ip}: {e}")


async def unblock_ip(ip: str):
    """Unblock IP via iptables."""
    if not is_valid_ip(ip):
        logging.warning(f"Invalid IP tried to unblock: {ip}")
        return
    cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        proc = await asyncio.create_subprocess_exec(*cmd)
        await proc.communicate()
        if proc.returncode == 0:
            blocked_ips.pop(ip, None)
            logging.info(f"Unblocked IP: {ip}")
        else:
            logging.error(f"Failed to unblock IP: {ip} (return code {proc.returncode})")
    except Exception as e:
        logging.error(f"Exception unblocking IP {ip}: {e}")


async def monitor_ip(ip: str, rate_limit, interval):
    """Track connection timestamps per IP, block if rate limit exceeded."""
    now = time.time()
    timestamps = connection_tracker[ip]

    # Remove timestamps outside the interval window
    while timestamps and now - timestamps[0] > interval:
        timestamps.popleft()

    timestamps.append(now)

    # Check rate limit and block if necessary
    if len(timestamps) > rate_limit and ip not in blocked_ips:
        logging.info(f"Rate limit exceeded for IP {ip}: {len(timestamps)} connections")
        await block_ip(ip)


async def unblock_expired(cooldown):
    """Unblock IPs whose cooldown has expired."""
    now = time.time()
    to_unblock = [ip for ip, t in blocked_ips.items() if now - t > cooldown]
    for ip in to_unblock:
        await unblock_ip(ip)


async def simulate_incoming_connections():
    """
    Simulate incoming IP connections.
    Replace this with real incoming IP reading code.
    """
    import random

    normal_ips = [f"192.168.1.{i}" for i in range(1, 10)]
    attacker_ip = "10.0.0.99"

    while True:
        # 10 normal, then 60 attacker requests, repeat
        for _ in range(10):
            yield random.choice(normal_ips)
        for _ in range(60):
            yield attacker_ip


async def read_real_ips():
    """
    Example function showing how to get real IPs from tcpdump.
    Replace 'tcpdump -n -l -i eth0 tcp' with your interface and filters.
    Requires root privileges.

    Yields IP addresses seen in incoming packets.
    """
    cmd = ["tcpdump", "-n", "-l", "-i", "eth0", "tcp"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )

    while running:
        line = await proc.stdout.readline()
        if not line:
            break
        line_str = line.decode()
        # Parse source IP from tcpdump output line (example):
        # 'IP 192.168.1.2.53940 > 10.0.0.1.80: Flags [S], seq 0, win 29200, options [mss 1460], length 0'
        try:
            parts = line_str.split()
            if parts[0] == "IP":
                src = parts[1]
                src_ip = src.split('.')[0:-1]  # Drop port part
                ip = ".".join(src_ip)
                if is_valid_ip(ip):
                    yield ip
        except Exception:
            continue


async def unblock_all():
    """Unblock all currently blocked IPs on shutdown."""
    logging.info("Unblocking all IPs before shutdown...")
    for ip in list(blocked_ips.keys()):
        await unblock_ip(ip)


def signal_handler(signum, frame):
    global running
    logging.info(f"Signal {signum} received, shutting down...")
    running = False


async def main():
    print_ascii_title()

    # Prompt user for configuration
    rate_limit = prompt_int("Enter maximum allowed connections per interval (RATE_LIMIT)", 50)
    interval = prompt_int("Enter time window in seconds to count connections (INTERVAL)", 60)
    cooldown = prompt_int("Enter cooldown time in seconds to block IPs (COOLDOWN)", 300)
    log_file = prompt_str("Enter log file path", "ddos_protect.log")

    setup_logging(log_file)

    # Register signals for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logging.info("Starting DDoS protection service...")

    # Choose your IP source here:
    # ip_source = simulate_incoming_connections()
    # Or use real network source (requires root and tcpdump installed)
    # ip_source = read_real_ips()

    ip_source = simulate_incoming_connections()  # Replace as needed

    while running:
        try:
            ip = await ip_source.__anext__()
        except StopAsyncIteration:
            # Restart generator if ended (simulate loop)
            ip_source = simulate_incoming_connections()
            ip = await ip_source.__anext__()

        await monitor_ip(ip, rate_limit, interval)
        await unblock_expired(cooldown)

        await asyncio.sleep(0.01)  # Small delay to yield control

    await unblock_all()
    logging.info("Service stopped.")


if __name__ == "__main__":
    asyncio.run(main())
