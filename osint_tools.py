import requests
import phonenumbers
from phonenumbers import geocoder, carrier
import whois
from rich.table import Table


PLATFORMS = [
    ("GitHub", "https://github.com/{}"),
    ("Twitter", "https://twitter.com/{}"),
    ("Instagram", "https://www.instagram.com/{}"),
    ("Reddit", "https://www.reddit.com/user/{}"),
    ("TikTok", "https://www.tiktok.com/@{}"),
    ("LinkedIn", "https://www.linkedin.com/in/{}"),
    ("Pinterest", "https://www.pinterest.com/{}"),
    ("YouTube", "https://www.youtube.com/@{}"),
    ("Twitch", "https://www.twitch.tv/{}"),
    ("Medium", "https://medium.com/@{}"),
    ("Dev.to", "https://dev.to/{}"),
    ("Keybase", "https://keybase.io/{}"),
    ("Replit", "https://replit.com/@{}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={}"),
    ("ProductHunt", "https://www.producthunt.com/@{}"),
]


class OSINTModules:

    def domain_whois(self, domain):
        table = Table(title=f"WHOIS: {domain}", show_header=True, header_style="bold yellow")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        try:
            w = whois.whois(domain)
            fields = {
                "Domain Name": w.domain_name,
                "Registrar": w.registrar,
                "Created": str(w.creation_date),
                "Expires": str(w.expiration_date),
                "Updated": str(w.updated_date),
                "Status": w.status,
                "Name Servers": w.name_servers,
                "Emails": w.emails,
                "Country": w.country,
                "Org": w.org,
            }
            for k, v in fields.items():
                val = ", ".join(v) if isinstance(v, list) else str(v) if v else "N/A"
                table.add_row(k, val[:120])
        except Exception as e:
            table.add_row("Error", str(e))

        return table

    def username_tracker(self, username):
        table = Table(title=f"Username Tracker: {username}", show_header=True, header_style="bold yellow")
        table.add_column("Platform", style="cyan")
        table.add_column("URL", style="white")
        table.add_column("Status", style="green")

        headers = {"User-Agent": "Mozilla/5.0"}
        for platform, url_template in PLATFORMS:
            url = url_template.format(username)
            try:
                r = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
                if r.status_code == 200:
                    status = "[green]Found[/green]"
                elif r.status_code == 404:
                    status = "[red]Not Found[/red]"
                else:
                    status = f"[yellow]HTTP {r.status_code}[/yellow]"
            except Exception:
                status = "[red]Error[/red]"
            table.add_row(platform, url, status)

        return table

    def ip_lookup(self, ip):
        table = Table(title=f"IP Lookup: {ip}", show_header=True, header_style="bold yellow")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = r.json()
            for key, val in data.items():
                table.add_row(str(key), str(val))
        except Exception as e:
            table.add_row("Error", str(e))

        return table

    def phone_lookup(self, number):
        table = Table(title=f"Phone Lookup: {number}", show_header=True, header_style="bold yellow")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")

        try:
            parsed = phonenumbers.parse(number, None)
            table.add_row("Valid", str(phonenumbers.is_valid_number(parsed)))
            table.add_row("Country", geocoder.description_for_number(parsed, "en"))
            table.add_row("Carrier", carrier.name_for_number(parsed, "en"))
            table.add_row("Number Type", str(phonenumbers.number_type(parsed)))
            table.add_row("International Format", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
            table.add_row("National Format", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL))
        except Exception as e:
            table.add_row("Error", str(e))

        return table
