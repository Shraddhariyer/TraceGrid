import dns.resolver


def get_dns_data(domain: str):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses = [str(rdata) for rdata in answers]

        return {
            "domain": domain,
            "ip_addresses": ip_addresses
        }

    except Exception as e:
        return {
            "domain": domain,
            "error": str(e)
        }
