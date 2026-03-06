from pyvis.network import Network
from app.services.neo4j_service import neo4j_service


def generate_graph(domain):
    query = """
    MATCH (d:Domain {name: $domain})-[r1]-(n1)
    OPTIONAL MATCH (n1)-[r2]-(n2)
    RETURN d, r1, n1, r2, n2
    """

    results = neo4j_service.run_query(query, {"domain": domain})

    net = Network(height="700px", width="100%", bgcolor="#111", font_color="white")

    added_nodes = set()

    def get_node_style(node):
        if "risk_score" in node:
            score = node.get("risk_score", 0)

            if score > 60:
                return {"color": "red", "size": 25}
            elif score > 30:
                return {"color": "orange", "size": 22}
            else:
                return {"color": "green", "size": 20}

        elif "address" in node:
            return {"color": "#00ccff", "size": 15}

        elif "name" in node:
            return {"color": "#aa66ff", "size": 15}

        return {"color": "white", "size": 10}

    for record in results:

        nodes = [record.get("d"), record.get("n1"), record.get("n2")]

        for node in nodes:
            if not node:
                continue

            node_id = node.get("name") or node.get("address")

            if node_id not in added_nodes:
                style = get_node_style(node)

                net.add_node(
                    node_id,
                    label=node_id,
                    color=style["color"],
                    size=style["size"]
                )

                added_nodes.add(node_id)

        # edges
        if record.get("n1"):
            source = record["d"].get("name")
            target = record["n1"].get("name") or record["n1"].get("address")

            net.add_edge(source, target)

        if record.get("n2"):
            source = record["n1"].get("name") or record["n1"].get("address")
            target = record["n2"].get("name") or record["n2"].get("address")

            net.add_edge(source, target)

    net.force_atlas_2based()
    net.write_html("graph.html")