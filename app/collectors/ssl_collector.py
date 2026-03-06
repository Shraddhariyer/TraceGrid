import requests

def get_domains_from_ssl(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url)

        data = response.json()

        domains = set()

        for entry in data:
            name = entry.get("name_value")
            if name:
                domains.update(name.split("\n"))

        return list(domains)

    except Exception as e:
        return []
