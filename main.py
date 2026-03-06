from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse

from app.services.neo4j_service import neo4j_service
from app.collectors.whois_collector import get_whois_data
from app.collectors.dns_collector import get_dns_data
from app.collectors.reverse_ip_collector import get_domains_from_ip
from app.collectors.ssl_collector import get_domains_from_ssl
from app.collectors.ns_collector import get_nameservers
from app.collectors.wayback_collector import get_wayback_data
from app.services.risk_engine import calculate_risk
from app.services.visualizer import generate_graph

app = FastAPI()


@app.get("/")
def home():
    return {"message": "TraceGrid is running"}


# ===============================
# DOMAIN ANALYSIS
# ===============================
@app.get("/analyze-domain")
def analyze_domain(domain: str):

    domain = domain.strip().lower()

    whois_data = get_whois_data(domain)
    dns_data = get_dns_data(domain)
    nameservers = get_nameservers(whois_data)
    ssl_domains = get_domains_from_ssl(domain)
    wayback_data = get_wayback_data(domain)

    # STORE DOMAIN
    neo4j_service.run_query("""
        MERGE (d:Domain {name: $domain})
        SET d.registrar = $registrar,
            d.creation_date = $creation,
            d.expiration_date = $expiry
    """, {
        "domain": domain,
        "registrar": whois_data.get("registrar"),
        "creation": whois_data.get("creation_date"),
        "expiry": whois_data.get("expiration_date")
    })

    # STORE IPs
    ip_list = dns_data.get("ip_addresses", [])
    for ip in ip_list:
        neo4j_service.run_query("""
            MERGE (d:Domain {name: $domain})
            MERGE (i:IP {address: $ip})
            MERGE (d)-[:HOSTED_ON]->(i)
        """, {"domain": domain, "ip": ip})

        # Reverse IP
        reverse_data = get_domains_from_ip(ip)
        if "domains" in reverse_data:
            for rd in reverse_data["domains"]:
                rd = rd.strip().lower()
                if rd == domain:
                    continue

                neo4j_service.run_query("""
                    MERGE (i:IP {address: $ip})
                    MERGE (d:Domain {name: $rd})
                    MERGE (d)-[:HOSTED_ON]->(i)
                """, {"ip": ip, "rd": rd})

    # STORE NS
    for ns in nameservers:
        ns = ns.lower()
        neo4j_service.run_query("""
            MERGE (d:Domain {name:$domain})
            MERGE (n:NameServer {name:$ns})
            MERGE (d)-[:USES_NS]->(n)
        """, {"domain": domain, "ns": ns})

    # SSL
    for sd in ssl_domains[:20]:
        sd = sd.lower()
        if sd == domain:
            continue

        neo4j_service.run_query("""
            MERGE (d:Domain {name:$domain})
            MERGE (s:Domain {name:$sd})
            MERGE (d)-[:SSL_RELATED]->(s)
        """, {"domain": domain, "sd": sd})

    # WAYBACK
    if wayback_data.get("status") == "ok":
        neo4j_service.run_query("""
            MERGE (d:Domain {name:$domain})
            SET d.snapshot_count=$count,
                d.first_seen=$first,
                d.last_seen=$last
        """, {
            "domain": domain,
            "count": wayback_data.get("snapshot_count"),
            "first": wayback_data.get("first_seen"),
            "last": wayback_data.get("last_seen")
        })

    # CLUSTER
    cluster_size = neo4j_service.get_cluster_size(domain)

    neo4j_service.run_query("""
        MERGE (d:Domain {name:$domain})
        SET d.cluster_size=$size
    """, {"domain": domain, "size": cluster_size})

    # RISK
    risk = calculate_risk(
        whois_data,
        dns_data,
        ssl_domains,
        wayback_data,
        cluster_size
    )

    neo4j_service.run_query("""
        MERGE (d:Domain {name:$domain})
        SET d.risk_score=$score,
            d.risk_reasons=$reasons
    """, {
        "domain": domain,
        "score": risk["score"],
        "reasons": ", ".join(risk["reasons"])
    })

    return {"status": "done", "risk": risk}


# ===============================
# GRAPH FILE
# ===============================
@app.get("/graph-file")
def graph_file(domain: str):
    generate_graph(domain)
    return FileResponse("graph.html")


# ===============================
# REPORT PAGE (UPGRADED)
# ===============================
@app.get("/report", response_class=HTMLResponse)
def report(domain: str):

    domain = domain.strip().lower()

    generate_graph(domain)

    result = neo4j_service.run_query("""
        MATCH (d:Domain {name:$domain})
        RETURN d
    """, {"domain": domain})

    if not result:
        return "<h2>Run /analyze-domain first</h2>"

    d = result[0]["d"]

    # ------------------------------
    # COUNTS
    # ------------------------------
    ip_count = len(neo4j_service.run_query("""
        MATCH (d:Domain {name:$domain})-[:HOSTED_ON]->(i)
        RETURN i
    """, {"domain": domain}))

    ns_count = len(neo4j_service.run_query("""
        MATCH (d:Domain {name:$domain})-[:USES_NS]->(n)
        RETURN n
    """, {"domain": domain}))

    ssl_count = len(neo4j_service.run_query("""
        MATCH (d:Domain {name:$domain})-[:SSL_RELATED]->(s)
        RETURN s
    """, {"domain": domain}))

    cluster_size = d.get("cluster_size", 1)
    risk_score = d.get("risk_score", 0)

    # ------------------------------
    # INSIGHTS ENGINE
    # ------------------------------
    insights = []

    if ip_count > 3:
        insights.append("Multiple IPs detected → load balancing OR fast-flux infrastructure")

    if cluster_size > 10:
        insights.append("Part of large cluster → possible fraud network")

    if ssl_count > 10:
        insights.append("Shared SSL → infrastructure reuse")

    if risk_score > 60:
        insights.append("High-risk domain → strong malicious indicators")

    if not insights:
        insights.append("No strong suspicious signals detected")

    # ------------------------------
    # COLOR
    # ------------------------------
    color = "green"
    if risk_score >= 70:
        color = "red"
    elif risk_score >= 40:
        color = "orange"

    # ------------------------------
    # HTML
    # ------------------------------
    html = f"""
    <html>
    <head>
        <title>TraceGrid Report</title>
        <style>
            body {{ background:#0d0d0d; color:white; font-family:Arial; padding:30px; }}
            .card {{ background:#1a1a1a; padding:20px; border-radius:12px; margin-bottom:20px; }}
            .risk {{ font-size:28px; font-weight:bold; color:{color}; }}
            iframe {{ width:100%; height:600px; border:none; }}
        </style>
    </head>
    <body>

        <h1>TraceGrid Intelligence Report</h1>

        <div class="card">
            <h2>{domain}</h2>
            <p class="risk">Risk Score: {risk_score}/100</p>
            <p><b>Cluster Size:</b> {cluster_size}</p>
        </div>

        <div class="card">
            <h3>Risk Reasons</h3>
            <p>{d.get("risk_reasons", "")}</p>
        </div>

        <div class="card">
            <h3>Insights</h3>
            <ul>{"".join(f"<li>{i}</li>" for i in insights)}</ul>
        </div>

        <div class="card">
            <h3>Infrastructure</h3>
            <p>IPs: {ip_count}</p>
            <p>NameServers: {ns_count}</p>
            <p>SSL Domains: {ssl_count}</p>
        </div>

        <div class="card">
            <h3>Graph Legend</h3>
            <p>🔴 Domain | 🔵 IP | 🟣 Nameserver</p>
        </div>

        <div class="card">
            <h3>Graph</h3>
            <iframe src="/graph-file?domain={domain}"></iframe>
        </div>

    </body>
    </html>
    """

    return HTMLResponse(content=html)