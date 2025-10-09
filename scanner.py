#!/usr/bin/env python3
"""
Network Scanner - A simple network scanning tool using Python and Nmap
"""

import sys
import socket
import argparse
import time
import nmap
import json
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
{Fore.YELLOW}                Network Scanner Tool v1.1
{Fore.YELLOW}        [Scans for open ports, services, and OS detection]
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

def scan_target(target, port_range=None, scan_type="-sS", detect_os=False, output_file=None):
    """
    Scan the target using nmap
    
    Parameters:
        target (str): IP address or domain name to scan
        port_range (str): Port range to scan (e.g., "1-1000")
        scan_type (str): Type of nmap scan to perform
        detect_os (bool): Whether to detect OS information
        output_file (str): File to save the scan results to
    """
    nm = nmap.PortScanner()
    
    # Default port range if not specified
    if not port_range:
        port_range = "1-1000"
    
    print(f"{Fore.BLUE}[*] Starting scan on {target}...")
    start_time = time.time()
    
    try:
        # Build the scan arguments
        arguments = f"{scan_type} -p {port_range}"
        
        # Add OS detection if requested
        if detect_os:
            print(f"{Fore.BLUE}[*] OS detection enabled...")
            arguments += " -O"
        
        # Run the scan
        nm.scan(target, arguments=arguments)
        
        # Calculate scan duration
        scan_time = time.time() - start_time
        
        # Check if the host is up
        if target in nm.all_hosts():
            hostname = nm[target].hostname() if 'hostname' in dir(nm[target]) and callable(nm[target].hostname) else 'Unknown'
            print(f"\n{Fore.GREEN}[+] Host: {target} ({hostname})")
            print(f"{Fore.GREEN}[+] State: {nm[target].state()}")
            print(f"{Fore.GREEN}[+] Scan completed in: {scan_time:.2f} seconds\n")
            
            # Display OS detection results if requested
            if detect_os and 'osmatch' in nm[target]:
                print(f"{Fore.YELLOW}[*] OS Detection Results:")
                print(f"{Fore.CYAN}╔{'═' * 70}╗")
                print(f"{Fore.CYAN}║ {'OS Name':<30} {'Accuracy':<10} {'OS Family':<25}║")
                print(f"{Fore.CYAN}╠{'═' * 70}╣")
                
                # Display the top OS matches
                for os in nm[target]['osmatch'][:3]:  # Show top 3 matches
                    name = os['name']
                    accuracy = os['accuracy']
                    family = os.get('osclass', [{}])[0].get('osfamily', 'Unknown') if os.get('osclass') else 'Unknown'
                    print(f"{Fore.CYAN}║ {Fore.GREEN}{name[:30]:<30} {accuracy + '%':<10} {family[:25]:<25}{Fore.CYAN}║")
                
                print(f"{Fore.CYAN}╚{'═' * 70}╝\n")
            
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
            
            # Save results to file if specified
            if output_file:
                try:
                    with open(output_file, 'w') as f:
                        if output_file.endswith('.json'):
                            # Convert scan data to JSON
                            json.dump(nm[target], f, indent=4)
                            print(f"\n{Fore.GREEN}[+] Scan results saved to {output_file} in JSON format")
                        else:
                            # Text format
                            f.write(f"Scan Results for {target}\n")
                            f.write(f"Host: {target} ({hostname})\n")
                            f.write(f"State: {nm[target].state()}\n\n")
                            
                            if detect_os and 'osmatch' in nm[target]:
                                f.write("OS Detection Results:\n")
                                for os in nm[target]['osmatch'][:3]:
                                    f.write(f"OS Name: {os['name']} (Accuracy: {os['accuracy']}%)\n")
                                f.write("\n")
                            
                            f.write("Open Ports and Services:\n")
                            if 'tcp' in nm[target]:
                                for port in nm[target]['tcp']:
                                    service = nm[target]['tcp'][port]
                                    if service['state'] == 'open':
                                        service_name = service['name']
                                        version = service['product'] if 'product' in service else 'Unknown'
                                        f.write(f"Port: {port}, Service: {service_name}, Version: {version}\n")
                            
                            print(f"\n{Fore.GREEN}[+] Scan results saved to {output_file} in text format")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error saving results to file: {e}")
            
            return True
        else:
            print(f"{Fore.RED}[-] Host {target} appears to be down or not responding.")
            return False
    
    except Exception as e:
        print(f"{Fore.RED}[!] Error during scan: {e}")
        return False

def scan_network(target_range, port_range=None, scan_type="-sS", detect_os=False, output_file=None):
    """
    Scan multiple targets in a network range
    
    Parameters:
        target_range (str): IP range in CIDR notation (e.g., "192.168.1.0/24")
        port_range (str): Port range to scan (e.g., "1-1000")
        scan_type (str): Type of nmap scan to perform
        detect_os (bool): Whether to detect OS information
        output_file (str): File to save the scan results to
    """
    print(f"{Fore.BLUE}[*] Starting network scan on {target_range}...")
    print(f"{Fore.BLUE}[*] This may take a while depending on the network size...\n")
    
    try:
        nm = nmap.PortScanner()
        
        # Default port range if not specified
        if not port_range:
            port_range = "22-25,80,443"  # Scan fewer ports for network scanning
        
        # Build the scan arguments
        arguments = f"-sn -T4"  # Fast ping scan to discover hosts
        nm.scan(hosts=target_range, arguments=arguments)
        
        # Get list of all hosts that are up
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        host_count = len(hosts_list)
        
        if host_count == 0:
            print(f"{Fore.RED}[!] No hosts found in the specified range.")
            return False
        
        print(f"{Fore.GREEN}[+] Found {host_count} active hosts in the network")
        print(f"{Fore.YELLOW}[*] Active hosts:")
        
        # Print the list of active hosts
        for host, status in hosts_list:
            hostname = nm[host].hostname() if 'hostname' in dir(nm[host]) and callable(nm[host].hostname) else 'Unknown'
            if hostname != 'Unknown':
                print(f"{Fore.GREEN}[+] {host} ({hostname}) - {status}")
            else:
                print(f"{Fore.GREEN}[+] {host} - {status}")
        
        # Ask if user wants to scan specific hosts
        print(f"\n{Fore.YELLOW}[*] Would you like to perform a detailed scan on a specific host? (y/n)")
        choice = input("> ")
        
        if choice.lower() == 'y':
            print(f"\n{Fore.YELLOW}[*] Enter the IP address of the host to scan:")
            host_to_scan = input("> ")
            
            if host_to_scan in nm.all_hosts():
                scan_target(host_to_scan, port_range, scan_type, detect_os, output_file)
            else:
                print(f"{Fore.RED}[!] Host {host_to_scan} is not in the discovered hosts list.")
        
        return True
    
    except Exception as e:
        print(f"{Fore.RED}[!] Error during network scan: {e}")
        return False

def main():
    """Main function to handle arguments and run the scan"""
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("target", help="Target IP address, domain name, or network range (CIDR notation)")
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-1000, 80, 22-25)", default="1-1000")
    parser.add_argument("-s", "--scan", help="Scan type (e.g., -sS for SYN scan, -sT for TCP connect)", default="-sS")
    parser.add_argument("-o", "--os-detect", action="store_true", help="Enable OS detection")
    parser.add_argument("-n", "--network", action="store_true", help="Treat target as a network range (CIDR notation)")
    parser.add_argument("-f", "--output-file", help="Save results to file (specify .json extension for JSON format)")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    if args.network:
        # Network range scan
        scan_network(args.target, args.ports, args.scan, args.os_detect, args.output_file)
    else:
        # Single target scan
        # Validate target
        ip = validate_target(args.target)
        if not ip:
            print(f"{Fore.RED}[!] Invalid target. Please provide a valid IP address or domain name.")
            sys.exit(1)
        
        # Run scan
        scan_target(ip, args.ports, args.scan, args.os_detect, args.output_file)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user.")
        sys.exit(0)