#!/usr/bin/env python3
"""
Advanced Port Scanner Tool
Enhanced version that provides real and accurate network results
"""

import socket
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import ipaddress

class AdvancedPortScanner:
    """
    Comprehensive class for scanning ports on target hosts
    """
    
    def __init__(self, timeout=2, max_threads=100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        
    def validate_target(self, target):
        """
        Validate target address (IP or Domain)
        """
        try:
            # Try to convert to IP address
            ipaddress.ip_address(target)
            return target
        except ValueError:
            try:
                # Try to resolve domain name to real IP
                resolved_ip = socket.gethostbyname(target)
                print(f"[+] Resolved {target} -> {resolved_ip}")
                return resolved_ip
            except socket.gaierror:
                raise ValueError(f"Invalid or unresolvable address: {target}")
    
    def scan_port(self, target, port):
        """
        Scan a single port with high accuracy
        """
        try:
            # Create new socket for each port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt to connect to the port
            result = sock.connect_ex((target, port))
            
            # Analyze the result
            if result == 0:
                # Port is open - try to identify service
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                result_info = {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'protocol': 'TCP'
                }
                self.open_ports.append(result_info)
                
            elif result == 111:  # Connection refused
                result_info = {
                    'port': port,
                    'status': 'closed',
                    'reason': 'connection refused'
                }
                self.closed_ports.append(result_info)
                
            else:
                # Filtered or unresponsive port
                result_info = {
                    'port': port,
                    'status': 'filtered',
                    'reason': f'error: {result}'
                }
                self.filtered_ports.append(result_info)
            
            sock.close()
            return result_info
            
        except socket.timeout:
            return {'port': port, 'status': 'filtered', 'reason': 'timeout'}
        except socket.error as e:
            return {'port': port, 'status': 'error', 'reason': str(e)}
        finally:
            try:
                sock.close()
            except:
                pass
    
    def scan_ports(self, target, ports):
        """
        Scan a list of ports using parallel processing
        """
        print(f"\n{'='*60}")
        print(f" Starting port scan on: {target}")
        print(f" Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        
        # Validate target first
        try:
            target_ip = self.validate_target(target)
        except ValueError as e:
            print(f"[-] Error: {e}")
            return
        
        print(f"\n[*] Scanning {len(ports)} ports...")
        print(f"[*] Using {self.max_threads} parallel threads\n")
        
        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Create tasks
            future_to_port = {
                executor.submit(self.scan_port, target_ip, port): port 
                for port in ports
            }
            
            # Process results
            completed = 0
            for future in as_completed(future_to_port):
                completed += 1
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result['status'] == 'open':
                        print(f"  [+] Port {port:<5} : open (service: {result.get('service', 'unknown')})")
                    elif result['status'] == 'closed':
                        print(f"  [-] Port {port:<5} : closed")
                    
                    # Show progress every 10 ports
                    if completed % 10 == 0:
                        print(f"  [*] Progress: {completed}/{len(ports)} ports")
                        
                except Exception as e:
                    print(f"  [!] Error scanning port {port}: {e}")
    
    def generate_report(self, target):
        """
        Generate detailed report with results
        """
        print(f"\n{'='*60}")
        print(f" Final Scan Report - {target}")
        print(f"{'='*60}")
        
        print(f"\n[+] Open ports ({len(self.open_ports)}):")
        if self.open_ports:
            for port_info in sorted(self.open_ports, key=lambda x: x['port']):
                print(f"    - Port {port_info['port']}: {port_info['service']}")
        else:
            print("    No open ports found")
        
        print(f"\n[-] Closed ports ({len(self.closed_ports)}): {len(self.closed_ports)}")
        print(f"[!] Filtered ports ({len(self.filtered_ports)}): {len(self.filtered_ports)}")
        
        # Save results to file
        filename = f"scan_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Port Scan Report for {target}\n")
            f.write(f"Date: {datetime.now()}\n")
            f.write(f"Open ports: {[p['port'] for p in self.open_ports]}\n")
            f.write(f"Total ports scanned: {len(self.open_ports) + len(self.closed_ports) + len(self.filtered_ports)}\n")
        
        print(f"\n[✓] Report saved to: {filename}")

def parse_ports(port_input):
    """
    Parse port input (supports ranges like 1-1000)
    """
    ports = []
    
    if '-' in port_input:
        # Port range
        start, end = map(int, port_input.split('-'))
        ports = list(range(start, end + 1))
    elif ',' in port_input:
        # Comma-separated ports
        ports = [int(p.strip()) for p in port_input.split(',')]
    else:
        # Single port
        ports = [int(port_input)]
    
    return ports

def main():
    """
    Main program function
    """
    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner - Real network results',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('target', help='Target (IP or Domain)')
    parser.add_argument('-p', '--ports', default='1-1024', 
                       help='Ports to scan (e.g., 80, 22-100, 443)')
    parser.add_argument('-t', '--timeout', type=int, default=2,
                       help='Connection timeout in seconds (default: 2)')
    parser.add_argument('-T', '--threads', type=int, default=100,
                       help='Number of parallel threads (default: 100)')
    
    args = parser.parse_args()
    
    try:
        # Parse requested ports
        ports_to_scan = parse_ports(args.ports)
        
        # Validate port numbers
        ports_to_scan = [p for p in ports_to_scan if 1 <= p <= 65535]
        
        if not ports_to_scan:
            print("[-] Error: Must specify valid ports (1-65535)")
            sys.exit(1)
        
        # Create scanner object
        scanner = AdvancedPortScanner(
            timeout=args.timeout,
            max_threads=args.threads
        )
        
        # Start scanning
        scanner.scan_ports(args.target, ports_to_scan)
        
        # Display report
        scanner.generate_report(args.target)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()