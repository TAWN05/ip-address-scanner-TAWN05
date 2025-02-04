#!/usr/bin/env python3
import sys
import ipaddress
import subprocess
import re
import socket
import csv

def ping_host(ip):
    """
    Pings the given IP address once with a 1-second timeout.
    Returns a tuple (status, response_time) where:
      - status: "UP", "DOWN", or "ERROR"
      - response_time: either a string like "2ms", "No response", or an error message.
    """
    try:
        # Run the ping command with one packet and a timeout of 1 second.
        # On Linux, "-c 1" sends 1 packet and "-W 1" sets a 1 second wait.
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            # Captures the output and errors
            capture_output=True,
            # returns the output as a string
            text=True
        )
        if result.returncode == 0:
            # Try to extract the response time from ping output using re.
            match = re.search(r'time=([\d\.]+) ms', result.stdout)
            ping_time = match.group(1) + "ms" if match else "N/A"
            status = "UP"
        else:
            # Distinguish between a host that is down and other errors.
            if "100% packet loss" in result.stdout:
                status = "DOWN"
                ping_time = "No response"
            else:
                status = "ERROR"
                # Use stderr if available; otherwise, fallback to stdout.
                ping_time = result.stderr.strip() or result.stdout.strip() or "Unknown error"
    except Exception as e:
        status = "ERROR"
        ping_time = str(e)
    return status, ping_time

def get_hostname(ip):
    """
    Performs a reverse DNS lookup for the given IP address.
    Returns the hostname if found, otherwise "Unknown".
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = "Unknown"
    return hostname

def get_mac(ip):
    """
    Attempts to retrieve the MAC address for the given IP address by checking
    the ARP (or neighbor) table. Returns the MAC address as a string if found,
    otherwise returns None.
    """
    try:
        # First, try using the ip neigh command
        result = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            # Example output: "192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"
            match = re.search(r'lladdr ([\da-fA-F:]+)', result.stdout)
            if match:
                return match.group(1)
        # Fallback: try using the "arp" command.
        result = subprocess.run(
            ["arp", "-n", ip],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            # Example line: "192.168.1.1  ether 00:11:22:33:44:55  C  eth0"
            match = re.search(r'([\da-fA-F:]{17})', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        return None
    return None

def main():
    # Validate command-line arguments.
    if len(sys.argv) != 2:
        print("Usage: python3 ip_scanner.py <CIDR>")
        sys.exit(1)
    
    cidr = sys.argv[1]
    try:
        # Allow non-strict networks so that e.g. 192.168.1.0/24 is acceptable.
        network = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        print(f"Invalid CIDR notation: {e}")
        sys.exit(1)
    
    print(f"Scanning network {cidr}...\n")
    
    results = []         # List to store the scan results (for CSV export)
    active_hosts = 0
    down_hosts = 0
    error_hosts = 0

    # Iterate over all valid host addresses (skips network and broadcast addresses).
    for ip in network.hosts():
        ip_str = str(ip)
        # Ping the host and capture the status and response time.
        status, ping_time = ping_host(ip_str)
        hostname = ""
        mac_address = ""
        
        if status == "UP":
            active_hosts += 1
            # Perform a reverse DNS lookup.
            hostname = get_hostname(ip_str)
            # Retrieve the MAC address (if available).
            mac = get_mac(ip_str)
            mac_address = mac if mac else "N/A"
        else:
            if status == "DOWN":
                down_hosts += 1
            else:
                error_hosts += 1

        # Output the scan result for this host.
        print(f"{ip_str} - {status} ({ping_time})")
        if hostname and hostname != "Unknown":
            print(f"Hostname: {hostname}")
        if mac_address and mac_address != "N/A":
            print(f"MAC: {mac_address}")
        print("")  # Blank line for readability

        # Save the result for CSV export.
        results.append({
            "IP": ip_str,
            "Status": status,
            "Response Time": ping_time,
            "Hostname": hostname,
            "MAC": mac_address
        })

    print(f"Scan complete. Found {active_hosts} active hosts, {down_hosts} down, {error_hosts} error\n")
    
    # Export the results to a CSV file.
    csv_filename = "scan_results.csv"
    try:
        with open(csv_filename, mode="w", newline="") as csvfile:
            fieldnames = ["IP", "Status", "Response Time", "Hostname", "MAC"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow(row)
        print(f"Results exported to {csv_filename}")
    except Exception as e:
        print(f"Error exporting to CSV: {e}")

if __name__ == "__main__":
    main()
