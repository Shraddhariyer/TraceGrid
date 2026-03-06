import whois


def format_date(date_value):
    if isinstance(date_value, list):
        return str(date_value[0])
    elif date_value:
        return str(date_value)
    return None


def get_whois_data(domain: str):
    try:
        data = whois.whois(domain)

        return {
            "domain": domain,
            "registrar": data.registrar,
            "creation_date": format_date(data.creation_date),
            "expiration_date": format_date(data.expiration_date),
            "name_servers": data.name_servers,
        }

    except Exception as e:
        return {
            "domain": domain,
            "error": str(e)
        }
