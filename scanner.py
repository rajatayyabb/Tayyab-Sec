import nmap
import socket
from rich.table import Table
from rich.text import Text
from scapy.all import ARP, Ether, srp


class PentestModules:

    def port_scanner(self, target):
        table = Table(title=f"Port Scan: {target}", show_header=True, header_style="bold cyan")
        table.add_column("Port", style="cyan")
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")

        try:
            nm = nmap.PortScanner()
            nm.scan(target, '1-1024', '-T4')

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name']
                        table.add_row(str(port), state, service)
        except Exception as e:
            table.add_row("Error", str(e), "-")

        return table

    def vulnerability_scanner(self, target):
        table = Table(title=f"Vulnerability Scan: {target}", show_header=True, header_style="bold red")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="yellow")
        table.add_column("Findings", style="red")

        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments='-sV --script=vuln -T4')

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        service = nm[host][proto][port].get('name', 'unknown')
                        script_output = nm[host][proto][port].get('script', {})
                        findings = "; ".join(script_output.values()) if script_output else "No issues found"
                        findings = findings[:100] + "..." if len(findings) > 100 else findings
                        table.add_row(str(port), service, findings)
        except Exception as e:
            table.add_row("Error", str(e), "-")

        return table

    def ip_pinger(self, target):
        table = Table(title=f"Ping: {target}", show_header=True, header_style="bold cyan")
        table.add_column("Host", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Latency", style="yellow")

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments='-sn')
            for host in nm.all_hosts():
                state = nm[host].state()
                latency = nm[host].get('tcpsequence', {}).get('values', 'N/A')
                table.add_row(host, state, str(latency))
            if not nm.all_hosts():
                table.add_row(target, "Host down / unreachable", "-")
        except Exception as e:
            table.add_row(target, f"Error: {e}", "-")

        return table

    def host_discovery(self, network):
        table = Table(title=f"Host Discovery: {network}", show_header=True, header_style="bold cyan")
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Status", style="green")

        try:
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=3, verbose=0)[0]

            for sent, received in result:
                table.add_row(received.psrc, received.hwsrc, "Up")

            if not result:
                table.add_row("No hosts found", "-", "-")
        except Exception as e:
            table.add_row("Error", str(e), "-")

        return table
