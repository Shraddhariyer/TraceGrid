import shodan
import os
from dotenv import load_dotenv

load_dotenv()

api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))


def get_domains_from_ip(ip: str):
    try:
        host = api.host(ip)

        domains = host.get("domains", [])

        return {
            "ip": ip,
            "domains": domains
        }

    except Exception as e:
        return {
            "ip": ip,
            "error": str(e)
        }
