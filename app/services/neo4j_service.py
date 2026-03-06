from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

# Load environment variables (.env locally, Render uses dashboard variables)
load_dotenv()

URI = os.getenv("NEO4J_URI")
USER = os.getenv("NEO4J_USER")
PASSWORD = os.getenv("NEO4J_PASSWORD")


class Neo4jService:
    def __init__(self):
        try:
            # Create Neo4j driver
            self.driver = GraphDatabase.driver(
                URI,
                auth=(USER, PASSWORD)
            )

            # Verify connection immediately (important for Aura)
            self.driver.verify_connectivity()

            print("✅ Connected to Neo4j Aura successfully")

        except Exception as e:
            print("❌ Neo4j connection failed:", e)
            raise e

    def close(self):
        if self.driver:
            self.driver.close()

    # 🔹 Generic query runner
    def run_query(self, query, parameters=None):
        try:
            with self.driver.session(database="neo4j") as session:
                result = session.run(query, parameters or {})
                return [record.data() for record in result]

        except Exception as e:
            print("❌ Query failed:", e)
            return []

    # 🔥 Get related domains (cluster detection)
    def get_related_domains(self, domain):

        query = """
        MATCH (d:Domain {name: $domain})

        OPTIONAL MATCH (d)-[:HOSTED_ON]->(i:IP)<-[:HOSTED_ON]-(d2:Domain)
        OPTIONAL MATCH (d)-[:USES_NS]->(n:NameServer)<-[:USES_NS]-(d3:Domain)
        OPTIONAL MATCH (d)-[:SSL_RELATED]->(d4:Domain)

        WITH
        COLLECT(DISTINCT d2.name) +
        COLLECT(DISTINCT d3.name) +
        COLLECT(DISTINCT d4.name) AS related

        UNWIND related AS domain_name
        WITH DISTINCT domain_name

        WHERE domain_name IS NOT NULL
        AND domain_name <> $domain

        RETURN domain_name
        """

        results = self.run_query(query, {"domain": domain})

        return [record["domain_name"] for record in results]

    # 🔥 Get cluster size
    def get_cluster_size(self, domain):

        related_domains = self.get_related_domains(domain)

        return len(related_domains)


# Create reusable service instance
neo4j_service = Neo4jService()