import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from rich.table import Table


SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "update", "confirm",
                       "banking", "paypal", "signin", "password", "credential"]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".pw"]


class UtilityModules:

    def url_phishing_analyzer(self, url):
        table = Table(title=f"Phishing Analysis: {url}", show_header=True, header_style="bold red")
        table.add_column("Check", style="cyan")
        table.add_column("Result", style="white")
        table.add_column("Risk", style="red")

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            full = url.lower()

            # HTTPS check
            https = parsed.scheme == "https"
            table.add_row("HTTPS", str(https), "[green]Low[/green]" if https else "[red]High[/red]")

            # Suspicious keywords
            found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
            table.add_row("Suspicious Keywords", ", ".join(found_kw) if found_kw else "None",
                          "[red]Medium[/red]" if found_kw else "[green]Low[/green]")

            # Suspicious TLD
            sus_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
            table.add_row("Suspicious TLD", domain.split(".")[-1], "[red]High[/red]" if sus_tld else "[green]Low[/green]")

            # IP address as domain
            ip_domain = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))
            table.add_row("IP as Domain", str(ip_domain), "[red]High[/red]" if ip_domain else "[green]Low[/green]")

            # Excessive subdomains
            subdomain_count = domain.count(".")
            table.add_row("Subdomain Count", str(subdomain_count),
                          "[red]High[/red]" if subdomain_count > 3 else "[green]Low[/green]")

            # Long URL
            long_url = len(url) > 100
            table.add_row("Long URL (>100 chars)", str(len(url)) + " chars",
                          "[yellow]Medium[/yellow]" if long_url else "[green]Low[/green]")

            # Special chars
            special_chars = url.count("-") + url.count("@")
            table.add_row("Special Chars (- @)", str(special_chars),
                          "[yellow]Medium[/yellow]" if special_chars > 3 else "[green]Low[/green]")

        except Exception as e:
            table.add_row("Error", str(e), "-")

        return table

    def website_cloner(self, url):
        table = Table(title=f"Website Cloner: {url}", show_header=True, header_style="bold green")
        table.add_column("Item", style="cyan")
        table.add_column("Details", style="white")

        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            r = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")

            filename = urlparse(url).netloc.replace(".", "_") + ".html"
            filepath = f"/tmp/{filename}"
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(r.text)

            table.add_row("Status Code", str(r.status_code))
            table.add_row("Page Title", soup.title.string if soup.title else "N/A")
            table.add_row("Content Length", f"{len(r.text)} chars")
            table.add_row("Links Found", str(len(soup.find_all("a"))))
            table.add_row("Images Found", str(len(soup.find_all("img"))))
            table.add_row("Forms Found", str(len(soup.find_all("form"))))
            table.add_row("Saved To", filepath)

        except Exception as e:
            table.add_row("Error", str(e))

        return table

    def cookie_security_auditor(self, url):
        table = Table(title=f"Cookie Audit: {url}", show_header=True, header_style="bold green")
        table.add_column("Cookie Name", style="cyan")
        table.add_column("HttpOnly", style="white")
        table.add_column("Secure", style="white")
        table.add_column("SameSite", style="white")
        table.add_column("Risk", style="red")

        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            r = requests.get(url, headers=headers, timeout=10)
            cookies = r.cookies

            if not cookies:
                table.add_row("No cookies found", "-", "-", "-", "[green]Low[/green]")
                return table

            for cookie in cookies:
                http_only = getattr(cookie, '_rest', {}).get('HttpOnly', None) is not None
                secure = cookie.secure
                same_site = getattr(cookie, '_rest', {}).get('SameSite', 'Not Set')

                risk_score = 0
                if not http_only:
                    risk_score += 1
                if not secure:
                    risk_score += 1
                if same_site in ('Not Set', 'None'):
                    risk_score += 1

                risk = "[green]Low[/green]" if risk_score == 0 else \
                       "[yellow]Medium[/yellow]" if risk_score == 1 else "[red]High[/red]"

                table.add_row(
                    cookie.name,
                    "[green]Yes[/green]" if http_only else "[red]No[/red]",
                    "[green]Yes[/green]" if secure else "[red]No[/red]",
                    str(same_site),
                    risk
                )

        except Exception as e:
            table.add_row("Error", str(e), "-", "-", "-")

        return table
