"""
Detailed analysis of Neo4j data to identify specific missing or incomplete fields.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import logging

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))
from neo4j_client import Neo4jClient

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def analyze_swc_completeness(client):
    """Analyze SWC data completeness."""
    logger.info("\n" + "="*80)
    logger.info("SWC DATA COMPLETENESS ANALYSIS")
    logger.info("="*80)

    with client.driver.session() as session:
        # Get all SWC nodes
        result = session.run("""
            MATCH (s:SWC)
            RETURN s
            ORDER BY s.swc_id
        """)
        swcs = [dict(record['s']) for record in result]

        missing_fields = {}
        for swc in swcs:
            swc_id = swc['swc_id']
            issues = []

            if not swc.get('title'):
                issues.append('title')
            if not swc.get('description'):
                issues.append('description')
            if not swc.get('remediation'):
                issues.append('remediation')
            if not swc.get('number'):
                issues.append('number')

            if issues:
                missing_fields[swc_id] = issues

        logger.info(f"\nTotal SWC nodes: {len(swcs)}")
        logger.info(f"Nodes with missing fields: {len(missing_fields)}")

        if missing_fields:
            logger.info("\n📋 SWC nodes with missing fields:")
            for swc_id, fields in missing_fields.items():
                logger.warning(f"  {swc_id}: missing {', '.join(fields)}")
        else:
            logger.info("✅ All SWC nodes have complete fields")

        # Check CWE mappings
        result = session.run("""
            MATCH (s:SWC)
            OPTIONAL MATCH (s)-[:MAPS_TO_CWE]->(c:CWE)
            RETURN s.swc_id as swc_id, c.cwe_id as cwe_id
            ORDER BY s.swc_id
        """)

        no_cwe = []
        for record in result:
            if not record['cwe_id']:
                no_cwe.append(record['swc_id'])

        logger.info(f"\nSWC nodes without CWE mapping: {len(no_cwe)}")
        if no_cwe:
            logger.info("📋 SWC nodes without CWE:")
            for swc_id in no_cwe:
                logger.info(f"  {swc_id}")


def analyze_owasp_completeness(client):
    """Analyze OWASP data completeness."""
    logger.info("\n" + "="*80)
    logger.info("OWASP DATA COMPLETENESS ANALYSIS")
    logger.info("="*80)

    with client.driver.session() as session:
        # Get all OWASP nodes
        result = session.run("""
            MATCH (o:OWASP_SC)
            RETURN o
            ORDER BY o.vulnerability_id
        """)
        owasps = [dict(record['o']) for record in result]

        missing_fields = {}
        for owasp in owasps:
            vuln_id = owasp['vulnerability_id']
            issues = []

            if not owasp.get('title'):
                issues.append('title')
            if not owasp.get('description'):
                issues.append('description')
            if not owasp.get('impact'):
                issues.append('impact')
            if not owasp.get('remediation'):
                issues.append('remediation')
            if not owasp.get('code'):
                issues.append('code')
            if not owasp.get('rank'):
                issues.append('rank')

            if issues:
                missing_fields[vuln_id] = issues

        logger.info(f"\nTotal OWASP nodes: {len(owasps)}")
        logger.info(f"Nodes with missing fields: {len(missing_fields)}")

        if missing_fields:
            logger.info("\n📋 OWASP nodes with missing fields:")
            for vuln_id, fields in missing_fields.items():
                logger.warning(f"  {vuln_id}: missing {', '.join(fields)}")
        else:
            logger.info("✅ All OWASP nodes have complete fields")


def analyze_scsvs_completeness(client):
    """Analyze SCSVS data completeness."""
    logger.info("\n" + "="*80)
    logger.info("SCSVS DATA COMPLETENESS ANALYSIS")
    logger.info("="*80)

    with client.driver.session() as session:
        # Get all SCSVS Category nodes
        result = session.run("""
            MATCH (sc:SCSVSCategory)
            RETURN sc
            ORDER BY sc.category_id
        """)
        categories = [dict(record['sc']) for record in result]

        missing_fields = {}
        for cat in categories:
            cat_id = cat['category_id']
            issues = []

            if not cat.get('name'):
                issues.append('name')
            if not cat.get('control_objective'):
                issues.append('control_objective')
            if not cat.get('category_type'):
                issues.append('category_type')

            if issues:
                missing_fields[cat_id] = issues

        logger.info(f"\nTotal SCSVS Category nodes: {len(categories)}")
        logger.info(f"Nodes with missing fields: {len(missing_fields)}")

        if missing_fields:
            logger.info("\n📋 SCSVS Categories with missing fields:")
            for cat_id, fields in missing_fields.items():
                logger.warning(f"  {cat_id}: missing {', '.join(fields)}")
        else:
            logger.info("✅ All SCSVS Category nodes have complete fields")

        # Get all SCSVS Requirement nodes
        result = session.run("""
            MATCH (sr:SCSVSRequirement)
            RETURN sr
            ORDER BY sr.requirement_id
        """)
        requirements = [dict(record['sr']) for record in result]

        missing_req_fields = {}
        for req in requirements:
            req_id = req['requirement_id']
            issues = []

            if not req.get('description'):
                issues.append('description')
            if not req.get('category_code'):
                issues.append('category_code')

            if issues:
                missing_req_fields[req_id] = issues

        logger.info(f"\nTotal SCSVS Requirement nodes: {len(requirements)}")
        logger.info(f"Nodes with missing fields: {len(missing_req_fields)}")

        if missing_req_fields:
            logger.info("\n📋 SCSVS Requirements with missing fields:")
            for req_id, fields in list(missing_req_fields.items())[:10]:  # Show first 10
                logger.warning(f"  {req_id}: missing {', '.join(fields)}")
            if len(missing_req_fields) > 10:
                logger.info(f"  ... and {len(missing_req_fields) - 10} more")
        else:
            logger.info("✅ All SCSVS Requirement nodes have complete fields")


def analyze_code_examples(client):
    """Analyze CodeExample nodes."""
    logger.info("\n" + "="*80)
    logger.info("CODE EXAMPLE ANALYSIS")
    logger.info("="*80)

    with client.driver.session() as session:
        # Get all CodeExample nodes
        result = session.run("""
            MATCH (ce:CodeExample)
            RETURN ce
            ORDER BY ce.example_id
        """)
        code_examples = [dict(record['ce']) for record in result]

        logger.info(f"\nTotal CodeExample nodes: {len(code_examples)}")

        # Count by type
        by_type = {}
        for ce in code_examples:
            ce_type = ce.get('example_type', 'unknown')
            by_type[ce_type] = by_type.get(ce_type, 0) + 1

        logger.info("\n📊 Code examples by type:")
        for ce_type, count in by_type.items():
            logger.info(f"  {ce_type}: {count}")

        # Count by source (SWC vs OWASP)
        swc_count = sum(1 for ce in code_examples if 'swc_id' in ce)
        owasp_count = sum(1 for ce in code_examples if 'vulnerability_id' in ce)

        logger.info(f"\n📊 Code examples by source:")
        logger.info(f"  From SWC: {swc_count}")
        logger.info(f"  From OWASP: {owasp_count}")

        # Check for missing fields
        missing_fields = {}
        for ce in code_examples:
            ce_id = ce['example_id']
            issues = []

            if not ce.get('code'):
                issues.append('code')
            if not ce.get('language'):
                issues.append('language')
            if not ce.get('example_type'):
                issues.append('example_type')

            if issues:
                missing_fields[ce_id] = issues

        if missing_fields:
            logger.info(f"\n⚠️  Code examples with missing fields: {len(missing_fields)}")
            for ce_id, fields in list(missing_fields.items())[:5]:  # Show first 5
                logger.warning(f"  {ce_id}: missing {', '.join(fields)}")
            if len(missing_fields) > 5:
                logger.info(f"  ... and {len(missing_fields) - 5} more")
        else:
            logger.info("\n✅ All CodeExample nodes have complete fields")

        # Sample a code example
        if code_examples:
            logger.info("\n📄 Sample Code Example:")
            sample = code_examples[0]
            for key, value in sample.items():
                if key == 'code':
                    logger.info(f"  {key}: [{len(value)} characters]")
                elif isinstance(value, str) and len(value) > 100:
                    logger.info(f"  {key}: {value[:100]}...")
                else:
                    logger.info(f"  {key}: {value}")


def analyze_relationships(client):
    """Analyze relationship completeness."""
    logger.info("\n" + "="*80)
    logger.info("RELATIONSHIP ANALYSIS")
    logger.info("="*80)

    with client.driver.session() as session:
        # Check for orphaned nodes
        result = session.run("""
            MATCH (s:SWC)
            WHERE NOT (s)-[:HAS_VULNERABLE_CODE|HAS_FIXED_CODE]->()
            RETURN count(s) as count
        """)
        orphaned_swc = result.single()['count']

        result = session.run("""
            MATCH (o:OWASP_SC)
            WHERE NOT (o)-[:HAS_VULNERABLE_CODE|HAS_FIXED_CODE]->()
            RETURN count(o) as count
        """)
        orphaned_owasp = result.single()['count']

        logger.info(f"\n📊 Orphaned nodes (without code examples):")
        logger.info(f"  SWC nodes: {orphaned_swc}")
        logger.info(f"  OWASP nodes: {orphaned_owasp}")

        if orphaned_swc > 0:
            result = session.run("""
                MATCH (s:SWC)
                WHERE NOT (s)-[:HAS_VULNERABLE_CODE|HAS_FIXED_CODE]->()
                RETURN s.swc_id as swc_id
                ORDER BY s.swc_id
            """)
            logger.info("\n📋 SWC nodes without code examples:")
            for record in result:
                logger.info(f"  {record['swc_id']}")

        if orphaned_owasp > 0:
            result = session.run("""
                MATCH (o:OWASP_SC)
                WHERE NOT (o)-[:HAS_VULNERABLE_CODE|HAS_FIXED_CODE]->()
                RETURN o.vulnerability_id as vuln_id
                ORDER BY o.vulnerability_id
            """)
            logger.info("\n📋 OWASP nodes without code examples:")
            for record in result:
                logger.info(f"  {record['vuln_id']}")


def main():
    """Main analysis function."""
    # Load environment variables
    load_dotenv()
    neo4j_uri = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
    neo4j_user = os.getenv('NEO4J_USER', 'neo4j')
    neo4j_password = os.getenv('NEO4J_PASSWORD')

    if not neo4j_password:
        logger.error("NEO4J_PASSWORD not set in environment")
        return

    # Connect to Neo4j
    logger.info(f"Connecting to Neo4j at {neo4j_uri}...")
    client = Neo4jClient(neo4j_uri, neo4j_user, neo4j_password)

    # Run analyses
    analyze_swc_completeness(client)
    analyze_owasp_completeness(client)
    analyze_scsvs_completeness(client)
    analyze_code_examples(client)
    analyze_relationships(client)

    # Close connection
    client.close()

    logger.info("\n" + "="*80)
    logger.info("ANALYSIS COMPLETE")
    logger.info("="*80)


if __name__ == '__main__':
    main()
