"""
Neo4j client module for managing database connections and operations.
Handles schema creation (constraints, indexes) and CRUD operations.
"""

from neo4j import GraphDatabase
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Client for interacting with Neo4j database."""

    def __init__(self, uri: str, username: str, password: str):
        """
        Initialize Neo4j connection.

        Args:
            uri: Neo4j database URI (e.g., 'bolt://localhost:7687')
            username: Database username
            password: Database password
        """
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        self._verify_connectivity()

    def _verify_connectivity(self):
        """Verify database connection."""
        try:
            self.driver.verify_connectivity()
            logger.info("Successfully connected to Neo4j database")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise

    def close(self):
        """Close the database connection."""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")

    def clear_database(self, domain_type: str = None):
        """
        Delete nodes and relationships in the database.

        Args:
            domain_type: If provided, only delete nodes with this type property.
                        If None, delete all nodes (default behavior).
        """
        with self.driver.session() as session:
            if domain_type:
                # Delete only nodes with specific domain type
                query = "MATCH (n {type: $domain_type}) DETACH DELETE n"
                session.run(query, domain_type=domain_type)
                logger.info(f"Database cleared for domain type: {domain_type}")
            else:
                # Delete all nodes
                session.run("MATCH (n) DETACH DELETE n")
                logger.info("Database cleared successfully (all data)")

    def create_constraints(self):
        """Create uniqueness constraints as defined in ontology schema."""
        constraints = [
            # VulnerabilityStandard
            "CREATE CONSTRAINT constraint_vuln_standard_id IF NOT EXISTS "
            "FOR (vs:VulnerabilityStandard) REQUIRE vs.id IS UNIQUE",

            # BugClass
            "CREATE CONSTRAINT constraint_bug_class_id IF NOT EXISTS "
            "FOR (bc:BugClass) REQUIRE bc.class_id IS UNIQUE",

            # OWASP_SC
            "CREATE CONSTRAINT constraint_owasp_id IF NOT EXISTS "
            "FOR (o:OWASP_SC) REQUIRE o.vulnerability_id IS UNIQUE",

            # SWC
            "CREATE CONSTRAINT constraint_swc_id IF NOT EXISTS "
            "FOR (s:SWC) REQUIRE s.swc_id IS UNIQUE",

            # CWE
            "CREATE CONSTRAINT constraint_cwe_id IF NOT EXISTS "
            "FOR (c:CWE) REQUIRE c.cwe_id IS UNIQUE",

            # SCSVSCategory
            "CREATE CONSTRAINT constraint_scsvs_category_id IF NOT EXISTS "
            "FOR (sc:SCSVSCategory) REQUIRE sc.category_id IS UNIQUE",

            # SCSVSRequirement
            "CREATE CONSTRAINT constraint_scsvs_req_id IF NOT EXISTS "
            "FOR (sr:SCSVSRequirement) REQUIRE sr.requirement_id IS UNIQUE",

            # CodeExample
            "CREATE CONSTRAINT constraint_code_example_id IF NOT EXISTS "
            "FOR (ce:CodeExample) REQUIRE ce.example_id IS UNIQUE",

            # MitigationPattern
            "CREATE CONSTRAINT constraint_mitigation_pattern_id IF NOT EXISTS "
            "FOR (mp:MitigationPattern) REQUIRE mp.pattern_id IS UNIQUE"
        ]

        with self.driver.session() as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                    logger.debug(f"Created constraint: {constraint[:50]}...")
                except Exception as e:
                    logger.warning(f"Constraint creation warning: {e}")

        logger.info("Constraints created successfully")

    def create_indexes(self):
        """Create indexes as defined in ontology schema."""
        indexes = [
            # Primary ID lookups
            "CREATE INDEX idx_vuln_standard_id IF NOT EXISTS FOR (vs:VulnerabilityStandard) ON (vs.id)",
            "CREATE INDEX idx_bug_class_id IF NOT EXISTS FOR (bc:BugClass) ON (bc.class_id)",
            "CREATE INDEX idx_owasp_vuln_id IF NOT EXISTS FOR (o:OWASP_SC) ON (o.vulnerability_id)",
            "CREATE INDEX idx_swc_id IF NOT EXISTS FOR (s:SWC) ON (s.swc_id)",
            "CREATE INDEX idx_cwe_id IF NOT EXISTS FOR (c:CWE) ON (c.cwe_id)",
            "CREATE INDEX idx_scsvs_category_id IF NOT EXISTS FOR (sc:SCSVSCategory) ON (sc.category_id)",
            "CREATE INDEX idx_scsvs_req_id IF NOT EXISTS FOR (sr:SCSVSRequirement) ON (sr.requirement_id)",
            "CREATE INDEX idx_code_example_id IF NOT EXISTS FOR (ce:CodeExample) ON (ce.example_id)",
            "CREATE INDEX idx_mitigation_pattern_id IF NOT EXISTS FOR (mp:MitigationPattern) ON (mp.pattern_id)",

            # Secondary property lookups
            "CREATE INDEX idx_owasp_code IF NOT EXISTS FOR (o:OWASP_SC) ON (o.code)",
            "CREATE INDEX idx_swc_number IF NOT EXISTS FOR (s:SWC) ON (s.number)",
            "CREATE INDEX idx_cwe_number IF NOT EXISTS FOR (c:CWE) ON (c.number)",
            "CREATE INDEX idx_code_type IF NOT EXISTS FOR (ce:CodeExample) ON (ce.type)",
            "CREATE INDEX idx_code_language IF NOT EXISTS FOR (ce:CodeExample) ON (ce.language)",
            "CREATE INDEX idx_scsvs_cat_type IF NOT EXISTS FOR (sc:SCSVSCategory) ON (sc.category_type)",

            # Version lookups
            "CREATE INDEX idx_owasp_version IF NOT EXISTS FOR (o:OWASP_SC) ON (o.version)",
            "CREATE INDEX idx_swc_version IF NOT EXISTS FOR (s:SWC) ON (s.version)",
            "CREATE INDEX idx_scsvs_cat_version IF NOT EXISTS FOR (sc:SCSVSCategory) ON (sc.version)",
            "CREATE INDEX idx_scsvs_req_version IF NOT EXISTS FOR (sr:SCSVSRequirement) ON (sr.version)",

            # Composite indexes
            "CREATE INDEX idx_code_type_lang IF NOT EXISTS FOR (ce:CodeExample) ON (ce.type, ce.language)",
            "CREATE INDEX idx_owasp_code_rank IF NOT EXISTS FOR (o:OWASP_SC) ON (o.code, o.rank)",
            "CREATE INDEX idx_owasp_version_code IF NOT EXISTS FOR (o:OWASP_SC) ON (o.version, o.code)",
            "CREATE INDEX idx_scsvs_version_category IF NOT EXISTS FOR (sc:SCSVSCategory) ON (sc.version, sc.category_id)"
        ]

        with self.driver.session() as session:
            for index in indexes:
                try:
                    session.run(index)
                    logger.debug(f"Created index: {index[:50]}...")
                except Exception as e:
                    logger.warning(f"Index creation warning: {e}")

        logger.info("Indexes created successfully")

    def create_fulltext_indexes(self):
        """Create full-text search indexes."""
        fulltext_indexes = [
            # Vulnerability text search
            "CREATE FULLTEXT INDEX idx_vuln_text_search IF NOT EXISTS "
            "FOR (n:OWASP_SC|SWC) ON EACH [n.title, n.description, n.remediation]",

            # Bug class text search
            "CREATE FULLTEXT INDEX idx_bug_class_text_search IF NOT EXISTS "
            "FOR (bc:BugClass) ON EACH [bc.name, bc.description]",

            # SCSVS requirements text search
            "CREATE FULLTEXT INDEX idx_scsvs_req_text_search IF NOT EXISTS "
            "FOR (sr:SCSVSRequirement) ON EACH [sr.description]",

            # Code examples text search
            "CREATE FULLTEXT INDEX idx_code_text_search IF NOT EXISTS "
            "FOR (ce:CodeExample) ON EACH [ce.code, ce.vulnerability_pattern, ce.fix_explanation]"
        ]

        with self.driver.session() as session:
            for index in fulltext_indexes:
                try:
                    session.run(index)
                    logger.debug(f"Created fulltext index: {index[:50]}...")
                except Exception as e:
                    logger.warning(f"Fulltext index creation warning: {e}")

        logger.info("Full-text indexes created successfully")

    def create_node(self, label: str, properties: Dict[str, Any],
                   id_property: str) -> Dict[str, Any]:
        """
        Create or merge a node with given label and properties.

        Args:
            label: Node label (e.g., 'OWASP_SC')
            properties: Node properties as dictionary
            id_property: Property name to use for MERGE (unique identifier)

        Returns:
            Created/merged node properties
        """
        # Filter out None values
        props = {k: v for k, v in properties.items() if v is not None}

        query = f"""
        MERGE (n:{label} {{{id_property}: $id_value}})
        SET n += $properties
        RETURN n
        """

        with self.driver.session() as session:
            result = session.run(
                query,
                id_value=props[id_property],
                properties=props
            )
            node = result.single()
            return dict(node['n']) if node else {}

    def create_relationship(self, from_id: str, from_label: str, from_id_prop: str,
                          to_id: str, to_label: str, to_id_prop: str,
                          rel_type: str, properties: Optional[Dict[str, Any]] = None):
        """
        Create a relationship between two nodes.

        Args:
            from_id: Source node ID value
            from_label: Source node label
            from_id_prop: Source node ID property name
            to_id: Target node ID value
            to_label: Target node label
            to_id_prop: Target node ID property name
            rel_type: Relationship type
            properties: Optional relationship properties
        """
        props = properties or {}
        # Filter out None values
        props = {k: v for k, v in props.items() if v is not None}

        # Build SET clause for relationship properties
        set_clause = ""
        if props:
            set_clause = "SET r += $properties"

        query = f"""
        MATCH (from:{from_label} {{{from_id_prop}: $from_id}})
        MATCH (to:{to_label} {{{to_id_prop}: $to_id}})
        MERGE (from)-[r:{rel_type}]->(to)
        {set_clause}
        RETURN r
        """

        with self.driver.session() as session:
            try:
                session.run(
                    query,
                    from_id=from_id,
                    to_id=to_id,
                    properties=props
                )
            except Exception as e:
                logger.error(f"Failed to create relationship {rel_type}: {e}")
                logger.error(f"From: {from_label}[{from_id_prop}={from_id}] "
                           f"To: {to_label}[{to_id_prop}={to_id}]")

    def batch_create_nodes(self, label: str, nodes: List[Dict[str, Any]],
                          id_property: str):
        """
        Create multiple nodes in a single transaction.

        Args:
            label: Node label
            nodes: List of node property dictionaries
            id_property: Property name to use for MERGE
        """
        query = f"""
        UNWIND $nodes as node
        MERGE (n:{label} {{`{id_property}`: node.{id_property}}})
        SET n += node
        """

        with self.driver.session() as session:
            session.run(query, nodes=nodes)
            logger.info(f"Batch created {len(nodes)} {label} nodes")

    def get_node_count(self, label: str) -> int:
        """Get count of nodes with given label."""
        with self.driver.session() as session:
            result = session.run(f"MATCH (n:{label}) RETURN count(n) as count")
            return result.single()['count']

    def get_relationship_count(self, rel_type: str) -> int:
        """Get count of relationships of given type."""
        with self.driver.session() as session:
            result = session.run(f"MATCH ()-[r:{rel_type}]->() RETURN count(r) as count")
            return result.single()['count']

    def get_database_stats(self) -> Dict[str, int]:
        """Get overall database statistics."""
        stats = {}

        # Node labels to count
        labels = [
            'VulnerabilityStandard', 'BugClass', 'OWASP_SC', 'SWC', 'CWE',
            'SCSVSCategory', 'SCSVSRequirement', 'CodeExample', 'MitigationPattern'
        ]

        for label in labels:
            stats[f'{label}_nodes'] = self.get_node_count(label)

        # Get all existing relationship types in the database
        with self.driver.session() as session:
            result = session.run("""
                CALL db.relationshipTypes() YIELD relationshipType
                RETURN relationshipType
            """)
            existing_rel_types = [record['relationshipType'] for record in result]

        # Only count relationships that actually exist
        for rel_type in existing_rel_types:
            stats[f'{rel_type}_relationships'] = self.get_relationship_count(rel_type)

        return stats
