def get_nameservers(whois_data):
    try:
        ns = whois_data.get("name_servers")

        if isinstance(ns, list):
            return [n.lower() for n in ns]
        elif ns:
            return [ns.lower()]

        return []

    except:
        return []
