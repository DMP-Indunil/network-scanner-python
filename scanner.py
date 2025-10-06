#!/usr/bin/env python3
"""
Network Scanner - A simple network scanning tool using Python and Nmap
"""

import sys
import socket
import argparse
import time
import nmap
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def print_banner():
    """Print a fancy banner for the tool"""
    banner = f"""
{Fore.CYAN}╔═════════════════════════════════════════════════╗
{Fore.CYAN}║ {Fore.GREEN}███    ██ ███████ ████████ {Fore.MAGENTA}███████  ██████  █████  ███    ██{Fore.CYAN} ║
{Fore.CYAN}║ {Fore.GREEN}████   ██ ██         ██    {Fore.MAGENTA}██      ██      ██   ██ ████   ██{Fore.CYAN} ║
{Fore.CYAN}║ {Fore.GREEN}██ ██  ██ █████      ██    {Fore.MAGENTA}███████ ██      ███████ ██ ██  ██{Fore.CYAN} ║
{Fore.CYAN}║ {Fore.GREEN}██  ██ ██ ██         ██    {Fore.MAGENTA}     ██ ██      ██   ██ ██  ██ ██{Fore.CYAN} ║
{Fore.CYAN}║ {Fore.GREEN}██   ████ ███████    ██    {Fore.MAGENTA}███████  ██████ ██   ██ ██   ████{Fore.CYAN} ║
{Fore.CYAN}╚═════════════════════════════════════════════════╝
{Fore.YELLOW}                Network Scanner Tool v1.0
{Fore.YELLOW}        [Scans for open ports and running services]
{Style.RESET_ALL}
    """
    print(banner)

def validate_target(target):
    """Validate IP address or domain name"""
    try:
        # Check if it's an IP address
        socket.inet_aton(target)
        return target
    except socket.error:
        # Check if it's a domain name
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

def scan_target(target, port_range=None, scan_type="-sS"):
    """
    Scan the target using nmap
    
    Parameters:
        target (str): IP address or domain name to scan
        port_range (str): Port range to scan (e.g., "1-1000")
        scan_type (str): Type of nmap scan to perform
    """
    nm = nmap.PortScanner()
    
    # Default port range if not specified
    if not port_range:
        port_range = "1-1000"
    
    print(f"{Fore.BLUE}[*] Starting scan on {target}...")
    start_time = time.time()
    
    try:
        # Run the scan
        arguments = f"{scan_type} -p {port_range}"
        nm.scan(target, arguments=arguments)
        
        # Calculate scan duration
        scan_time = time.time() - start_time
        
        # Check if the host is up
        if target in nm.all_hosts():
            print(f"\n{Fore.GREEN}[+] Host: {target} ({nm[target].hostname() if 'hostname' in dir(nm[target]) and callable(nm[target].hostname) else 'Unknown'})")
            print(f"{Fore.GREEN}[+] State: {nm[target].state()}")
            print(f"{Fore.GREEN}[+] Scan completed in: {scan_time:.2f} seconds\n")
            
            # Print open ports and services
            print(f"{Fore.YELLOW}[*] Open ports and services:")
            print(f"{Fore.CYAN}╔{'═' * 60}╗")
            print(f"{Fore.CYAN}║ {'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'VERSION':<20}║")
            print(f"{Fore.CYAN}╠{'═' * 60}╣")
            
            # Check if any tcp ports are available
            if 'tcp' in nm[target]:
                for port in nm[target]['tcp']:
                    service = nm[target]['tcp'][port]
                    state = service['state']
                    
                    if state == 'open':
                        service_name = service['name']
                        version = service['product'] if 'product' in service else 'Unknown'
                        print(f"{Fore.CYAN}║ {Fore.GREEN}{port:<10} {state:<10} {service_name:<15} {version[:20]:<20}{Fore.CYAN}║")
            
            print(f"{Fore.CYAN}╚{'═' * 60}╝")
            return True
        else:
            print(f"{Fore.RED}[-] Host {target} appears to be down or not responding.")
            return False
    
    except Exception as e:
        print(f"{Fore.RED}[!] Error during scan: {e}")
        return False

def main():
    """Main function to handle arguments and run the scan"""
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("target", help="Target IP address or domain name")
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-1000, 80, 22-25)", default="1-1000")
    parser.add_argument("-s", "--scan", help="Scan type (e.g., -sS for SYN scan, -sT for TCP connect)", default="-sS")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Validate target
    ip = validate_target(args.target)
    if not ip:
        print(f"{Fore.RED}[!] Invalid target. Please provide a valid IP address or domain name.")
        sys.exit(1)
    
    # Run scan
    scan_target(ip, args.ports, args.scan)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.")
        sys.exit(0)