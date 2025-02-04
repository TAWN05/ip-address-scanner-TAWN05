# IP Scanner

A lightweight Python-based network scanner that pings a range of IP addresses provided in CIDR notation. It checks each host's availability, retrieves response times, performs reverse DNS lookups, and attempts to obtain MAC addresses from the ARP/neighbor table. The results are printed to the terminal and exported to a CSV.

----------

## Table of Contents

-   [Installation](#installation)
-   [Usage](#usage)
-   [Features](#features)
-   [Tools](#tools)
-   [Contact Information & Support](#contact-information--support)

----------

## Installation

1.  **Prerequisites:**
    
    -   **Python 3:** Ensure you have Python 3 installed on your system.
    -   **Operating System:** This script is designed for Unix-like systems (Linux/macOS). Windows users may need to adjust the `ping` command options.
    -   **Network Tools:** The script uses system commands like `ping`, `ip neigh`, and `arp` which should be available on your system.
2.  **Clone the Repository:**
    
    ```bash
    git clone https://github.com/WTCSC/ip-address-scanner-TAWN05.git
    cd ip-scanner
    
    ```
    
3.  **No External Python Packages Required:**  
    The script uses only Python's standard library modules (`ipaddress`, `subprocess`, `re`, `socket`, and `csv`).
    

----------

## Usage

Run the script from the command line by providing a CIDR notation as an argument. For example, to scan the network `192.168.1.0/24`:

```bash
python3 ip_scanner.py 192.168.1.0/24

```

The script will:

-   Iterate over all valid host addresses (skipping the network and broadcast addresses).
-   Ping each host and report its status (UP, DOWN, or ERROR) along with the response time.
-   If a host is up, do a reverse DNS lookup and attempt to retrieve its MAC address.
-   Display detailed output for each host and export the complete results to a CSV file (`scan_results.csv`).

----------

## Features

-   **CIDR Notation Input:** Scan a network by specifying a CIDR (e.g., `192.168.1.0/24`).
-   **Ping Scanning:** Checks host availability by sending one ICMP packet per host.
-   **Response Time Extraction:** Parses the ping output to extract and display the response time in milliseconds.
-   **Reverse DNS Lookup:** Retrieves hostnames for active IP addresses.
-   **MAC Address Detection:** Attempts to find MAC addresses using `ip neigh` or `arp`.
-   **CSV Export:** Saves the scan results to a CSV file for easy analysis.

----------

## Tools

-   **Python 3:** The script is written entirely in Python.
-   **Standard Libraries:**
    -   `ipaddress`: For handling and iterating over CIDR network ranges.
    -   `subprocess`: To execute system commands (ping, ip neigh, arp).
    -   `re`: For extracting response times and MAC addresses using regular expressions.
    -   `socket`: To perform reverse DNS lookups.
    -   `csv`: To export scan results.
-   **System Commands:**  
    uses native network commands available on Linux systems

----------

## Contact Information & Support

If you have questions, need help, or would like to provide feedback, please contact:

-   **Email:** Jacobrcasey135@gmail.com
