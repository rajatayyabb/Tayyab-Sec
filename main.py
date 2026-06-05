import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

from modules.pentesting.scanner import PentestModules
from modules.osint.osint_tools import OSINTModules
from modules.utilities.util_tools import UtilityModules

console = Console()
pentest = PentestModules()
osint = OSINTModules()
utils = UtilityModules()

def display_banner():
    banner_text = """
    ███╗   ███╗██╗   ██╗███╗   ██╗██╗███████╗
    ████╗ ████║██║   ██║████╗  ██║██║██╔════╝
    ██╔████╔██║██║   ██║██╔██╗ ██║██║███████╗
    ██║╚██╔╝██║██║   ██║██║╚██╗██║██║╚════██║
    ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║███████║
    ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚══════╝
    [ TAYYAB-SEC MULTIPURPOSE TOOLKIT ]
    [      Developed by Tayyab       ]
    """
    console.print(Text(banner_text, style="bold red"))

def display_menu():
    table = Table(show_header=False, box=None)
    table.add_column("Pentesting", style="cyan")
    table.add_column("Osint", style="yellow")
    table.add_column("Utilities", style="green")
    
    table.add_row("[Pentesting]", "[Osint]", "[Utilities]")
    table.add_row("[01] Advanced Scanner", "[07] Domain Whois", "[15] URL Phishing Analyzer")
    table.add_row("[02] Vulnerability Scanner", "[08] Username Tracker", "[16] Website Cloner")
    table.add_row("[03] Port Scanner", "[09] IP Lookup", "[17] Cookie Security Auditor")
    table.add_row("[04] IP Pinger", "[10] Phone Number Lookup", "")
    table.add_row("[05] Host Discovery", "", "")
    
    console.print(Panel(table, title="[bold white]Main Menu[/bold white]", border_style="blue"))

def main():
    while True:
        os.system('clear')
        display_banner()
        display_menu()
        choice = Prompt.ask("[bold white]Select an option (or 'exit')[/bold white]")
        
        if choice == '01' or choice == '03':
            target = Prompt.ask("Enter target IP/Domain")
            results = pentest.port_scanner(target)
            console.print(results)
        elif choice == '02':
            target = Prompt.ask("Enter target IP/Domain")
            results = pentest.vulnerability_scanner(target)
            console.print(results)
        elif choice == '04':
            target = Prompt.ask("Enter target IP")
            results = pentest.ip_pinger(target)
            console.print(results)
        elif choice == '05':
            network = Prompt.ask("Enter network (e.g., 192.168.1.0/24)")
            results = pentest.host_discovery(network)
            console.print(results)
        elif choice == '07':
            domain = Prompt.ask("Enter domain")
            results = osint.domain_whois(domain)
            console.print(results)
        elif choice == '08':
            username = Prompt.ask("Enter username")
            results = osint.username_tracker(username)
            console.print(results)
        elif choice == '09':
            ip = Prompt.ask("Enter IP")
            results = osint.ip_lookup(ip)
            console.print(results)
        elif choice == '10':
            number = Prompt.ask("Enter phone number (with country code)")
            results = osint.phone_lookup(number)
            console.print(results)
        elif choice == '15':
            url = Prompt.ask("Enter URL to analyze")
            results = utils.url_phishing_analyzer(url)
            console.print(results)
        elif choice == '16':
            url = Prompt.ask("Enter URL to clone")
            results = utils.website_cloner(url)
            console.print(results)
        elif choice == '17':
            url = Prompt.ask("Enter URL to audit")
            results = utils.cookie_security_auditor(url)
            console.print(results)
        elif choice.lower() == 'exit':
            break
        else:
            console.print("[red]Invalid choice, please try again.[/red]")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
