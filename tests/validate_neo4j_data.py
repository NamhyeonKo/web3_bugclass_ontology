"""
Script to validate Neo4j data against source documents.
Identifies missing or incorrectly parsed values.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import logging

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))
from neo4j_client import Neo4jClient
from parsers.swc_parser import SWCParser
from parsers.owasp_parser import OWASPParser
from parsers.scsvs_parser import SCSVSParser
import config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DataValidator:
    """Validates Neo4j data against source documents."""

    def __init__(self, neo4j_client: Neo4jClient):
        self.client = neo4j_client

    def validate_swc_data(self, parsed_swcs, parsed_cwes, parsed_codes):
        """Validate SWC data in Neo4j."""
        logger.info("\n" + "="*80)
        logger.info("VALIDATING SWC DATA")
        logger.info("="*80)

        # Get data from Neo4j
        with self.client.driver.session() as session:
            # Get SWC nodes
            result = session.run("MATCH (s:SWC) RETURN s ORDER BY s.swc_id")
            db_swcs = {record['s']['swc_id']: dict(record['s']) for record in result}

            # Get CWE nodes
            result = session.run("MATCH (c:CWE) RETURN c ORDER BY c.cwe_id")
            db_cwes = {record['c']['cwe_id']: dict(record['c']) for record in result}

            # Get CodeExample nodes
            result = session.run("MATCH (ce:CodeExample) WHERE ce.swc_id IS NOT NULL RETURN ce")
            db_codes = [dict(record['ce']) for record in result]

        # Validate SWC nodes
        logger.info(f"\n📊 SWC Nodes Comparison:")
        logger.info(f"  Parsed from files: {len(parsed_swcs)}")
        logger.info(f"  Found in Neo4j: {len(db_swcs)}")

        missing_swcs = []
        incomplete_swcs = []

        for swc in parsed_swcs:
            swc_id = swc['swc_id']
            if swc_id not in db_swcs:
                missing_swcs.append(swc_id)
                logger.error(f"❌ Missing SWC node: {swc_id}")
            else:
                db_swc = db_swcs[swc_id]
                # Check for missing fields
                issues = []
                if not db_swc.get('title'):
                    issues.append('title')
                if not db_swc.get('description'):
                    issues.append('description')
                if not db_swc.get('remediation'):
                    issues.append('remediation')

                if issues:
                    incomplete_swcs.append((swc_id, issues))
                    logger.warning(f"⚠️  {swc_id} missing fields: {', '.join(issues)}")

        # Validate CWE nodes
        logger.info(f"\n📊 CWE Nodes Comparison:")
        logger.info(f"  Parsed from files: {len(parsed_cwes)}")
        logger.info(f"  Found in Neo4j: {len(db_cwes)}")

        missing_cwes = []
        for cwe in parsed_cwes:
            cwe_id = cwe['cwe_id']
            if cwe_id not in db_cwes:
                missing_cwes.append(cwe_id)
                logger.error(f"❌ Missing CWE node: {cwe_id}")

        # Validate Code Examples
        logger.info(f"\n📊 Code Examples Comparison:")
        logger.info(f"  Parsed from files: {len(parsed_codes)}")
        logger.info(f"  Found in Neo4j: {len(db_codes)}")

        if len(parsed_codes) != len(db_codes):
            logger.warning(f"⚠️  Code example count mismatch!")

        # Validate relationships
        with self.client.driver.session() as session:
            # SWC -> CWE relationships
            result = session.run("""
                MATCH (s:SWC)-[r:MAPS_TO_CWE]->(c:CWE)
                RETURN count(r) as count
            """)
            swc_cwe_count = result.single()['count']
            logger.info(f"\n📊 SWC -> CWE Relationships: {swc_cwe_count}")

            # SWC -> CodeExample relationships
            result = session.run("""
                MATCH (s:SWC)-[r:HAS_VULNERABLE_CODE|HAS_FIXED_CODE]->(ce:CodeExample)
                RETURN count(r) as count
            """)
            swc_code_count = result.single()['count']
            logger.info(f"📊 SWC -> CodeExample Relationships: {swc_code_count}")

        # Summary
        logger.info("\n" + "="*80)
        logger.info("SWC VALIDATION SUMMARY")
        logger.info("="*80)
        if missing_swcs:
            logger.error(f"❌ {len(missing_swcs)} missing SWC nodes")
        if incomplete_swcs:
            logger.warning(f"⚠️  {len(incomplete_swcs)} incomplete SWC nodes")
        if missing_cwes:
            logger.error(f"❌ {len(missing_cwes)} missing CWE nodes")

        if not missing_swcs and not incomplete_swcs and not missing_cwes:
            logger.info("✅ All SWC data validated successfully!")

        return {
            'missing_swcs': missing_swcs,
            'incomplete_swcs': incomplete_swcs,
            'missing_cwes': missing_cwes
        }

    def validate_owasp_data(self, parsed_vulns, parsed_codes):
        """Validate OWASP data in Neo4j."""
        logger.info("\n" + "="*80)
        logger.info("VALIDATING OWASP DATA")
        logger.info("="*80)

        # Get data from Neo4j
        with self.client.driver.session() as session:
            # Get OWASP nodes
            result = session.run("MATCH (o:OWASP_SC) RETURN o ORDER BY o.vulnerability_id")
            db_vulns = {record['o']['vulnerability_id']: dict(record['o']) for record in result}

            # Get CodeExample nodes
            result = session.run("MATCH (ce:CodeExample) WHERE ce.vulnerability_id IS NOT NULL RETURN ce")
            db_codes = [dict(record['ce']) for record in result]

        # Validate OWASP nodes
        logger.info(f"\n📊 OWASP Nodes Comparison:")
        logger.info(f"  Parsed from files: {len(parsed_vulns)}")
        logger.info(f"  Found in Neo4j: {len(db_vulns)}")

        missing_vulns = []
        incomplete_vulns = []

        for vuln in parsed_vulns:
            vuln_id = vuln['vulnerability_id']
            if vuln_id not in db_vulns:
                missing_vulns.append(vuln_id)
                logger.error(f"❌ Missing OWASP node: {vuln_id}")
            else:
                db_vuln = db_vulns[vuln_id]
                # Check for missing fields
                issues = []
                if not db_vuln.get('title'):
                    issues.append('title')
                if not db_vuln.get('description'):
                    issues.append('description')
                if not db_vuln.get('impact'):
                    issues.append('impact')
                if not db_vuln.get('remediation'):
                    issues.append('remediation')

                if issues:
                    incomplete_vulns.append((vuln_id, issues))
                    logger.warning(f"⚠️  {vuln_id} missing fields: {', '.join(issues)}")

        # Validate Code Examples
        logger.info(f"\n📊 Code Examples Comparison:")
        logger.info(f"  Parsed from files: {len(parsed_codes)}")
        logger.info(f"  Found in Neo4j: {len(db_codes)}")

        if len(parsed_codes) != len(db_codes):
            logger.warning(f"⚠️  Code example count mismatch!")

        # Validate relationships
        with self.client.driver.session() as session:
            # OWASP -> CodeExample relationships
            result = session.run("""
                MATCH (o:OWASP_SC)-[r:HAS_VULNERABLE_CODE|HAS_FIXED_CODE]->(ce:CodeExample)
                RETURN count(r) as count
            """)
            owasp_code_count = result.single()['count']
            logger.info(f"\n📊 OWASP -> CodeExample Relationships: {owasp_code_count}")

        # Summary
        logger.info("\n" + "="*80)
        logger.info("OWASP VALIDATION SUMMARY")
        logger.info("="*80)
        if missing_vulns:
            logger.error(f"❌ {len(missing_vulns)} missing OWASP nodes")
        if incomplete_vulns:
            logger.warning(f"⚠️  {len(incomplete_vulns)} incomplete OWASP nodes")

        if not missing_vulns and not incomplete_vulns:
            logger.info("✅ All OWASP data validated successfully!")

        return {
            'missing_vulns': missing_vulns,
            'incomplete_vulns': incomplete_vulns
        }

    def validate_scsvs_data(self, parsed_categories, parsed_requirements):
        """Validate SCSVS data in Neo4j."""
        logger.info("\n" + "="*80)
        logger.info("VALIDATING SCSVS DATA")
        logger.info("="*80)

        # Get data from Neo4j
        with self.client.driver.session() as session:
            # Get SCSVS Category nodes
            result = session.run("MATCH (sc:SCSVSCategory) RETURN sc ORDER BY sc.category_id")
            db_cats = {record['sc']['category_id']: dict(record['sc']) for record in result}

            # Get SCSVS Requirement nodes
            result = session.run("MATCH (sr:SCSVSRequirement) RETURN sr ORDER BY sr.requirement_id")
            db_reqs = {record['sr']['requirement_id']: dict(record['sr']) for record in result}

        # Validate Category nodes
        logger.info(f"\n📊 SCSVS Category Nodes Comparison:")
        logger.info(f"  Parsed from files: {len(parsed_categories)}")
        logger.info(f"  Found in Neo4j: {len(db_cats)}")

        missing_cats = []
        incomplete_cats = []

        for cat in parsed_categories:
            cat_id = cat['category_id']
            if cat_id not in db_cats:
                missing_cats.append(cat_id)
                logger.error(f"❌ Missing SCSVS Category: {cat_id}")
            else:
                db_cat = db_cats[cat_id]
                # Check for missing fields
                issues = []
                if not db_cat.get('name'):
                    issues.append('name')
                if not db_cat.get('control_objective'):
                    issues.append('control_objective')

                if issues:
                    incomplete_cats.append((cat_id, issues))
                    logger.warning(f"⚠️  {cat_id} missing fields: {', '.join(issues)}")

        # Validate Requirement nodes
        logger.info(f"\n📊 SCSVS Requirement Nodes Comparison:")
        logger.info(f"  Parsed from files: {len(parsed_requirements)}")
        logger.info(f"  Found in Neo4j: {len(db_reqs)}")

        missing_reqs = []
        incomplete_reqs = []

        for req in parsed_requirements:
            req_id = req['requirement_id']
            if req_id not in db_reqs:
                missing_reqs.append(req_id)
                logger.error(f"❌ Missing SCSVS Requirement: {req_id}")
            else:
                db_req = db_reqs[req_id]
                # Check for missing fields
                issues = []
                if not db_req.get('description'):
                    issues.append('description')

                if issues:
                    incomplete_reqs.append((req_id, issues))
                    logger.warning(f"⚠️  {req_id} missing fields: {', '.join(issues)}")

        # Validate relationships
        with self.client.driver.session() as session:
            # Category -> Requirement relationships
            result = session.run("""
                MATCH (sc:SCSVSCategory)-[r:HAS_REQUIREMENT]->(sr:SCSVSRequirement)
                RETURN count(r) as count
            """)
            cat_req_count = result.single()['count']
            logger.info(f"\n📊 Category -> Requirement Relationships: {cat_req_count}")

        # Summary
        logger.info("\n" + "="*80)
        logger.info("SCSVS VALIDATION SUMMARY")
        logger.info("="*80)
        if missing_cats:
            logger.error(f"❌ {len(missing_cats)} missing SCSVS categories")
        if incomplete_cats:
            logger.warning(f"⚠️  {len(incomplete_cats)} incomplete SCSVS categories")
        if missing_reqs:
            logger.error(f"❌ {len(missing_reqs)} missing SCSVS requirements")
        if incomplete_reqs:
            logger.warning(f"⚠️  {len(incomplete_reqs)} incomplete SCSVS requirements")

        if not missing_cats and not incomplete_cats and not missing_reqs and not incomplete_reqs:
            logger.info("✅ All SCSVS data validated successfully!")

        return {
            'missing_cats': missing_cats,
            'incomplete_cats': incomplete_cats,
            'missing_reqs': missing_reqs,
            'incomplete_reqs': incomplete_reqs
        }

    def print_sample_data(self):
        """Print sample data from Neo4j for inspection."""
        logger.info("\n" + "="*80)
        logger.info("SAMPLE DATA FROM NEO4J")
        logger.info("="*80)

        with self.client.driver.session() as session:
            # Sample SWC
            result = session.run("MATCH (s:SWC) RETURN s LIMIT 1")
            record = result.single()
            if record:
                logger.info("\n📄 Sample SWC Node:")
                swc = dict(record['s'])
                for key, value in swc.items():
                    if isinstance(value, str) and len(value) > 100:
                        logger.info(f"  {key}: {value[:100]}...")
                    else:
                        logger.info(f"  {key}: {value}")

            # Sample OWASP
            result = session.run("MATCH (o:OWASP_SC) RETURN o LIMIT 1")
            record = result.single()
            if record:
                logger.info("\n📄 Sample OWASP Node:")
                owasp = dict(record['o'])
                for key, value in owasp.items():
                    if isinstance(value, str) and len(value) > 100:
                        logger.info(f"  {key}: {value[:100]}...")
                    else:
                        logger.info(f"  {key}: {value}")

            # Sample SCSVS Category
            result = session.run("MATCH (sc:SCSVSCategory) RETURN sc LIMIT 1")
            record = result.single()
            if record:
                logger.info("\n📄 Sample SCSVS Category Node:")
                cat = dict(record['sc'])
                for key, value in cat.items():
                    if isinstance(value, str) and len(value) > 100:
                        logger.info(f"  {key}: {value[:100]}...")
                    else:
                        logger.info(f"  {key}: {value}")

            # Sample SCSVS Requirement
            result = session.run("MATCH (sr:SCSVSRequirement) RETURN sr LIMIT 1")
            record = result.single()
            if record:
                logger.info("\n📄 Sample SCSVS Requirement Node:")
                req = dict(record['sr'])
                for key, value in req.items():
                    if isinstance(value, str) and len(value) > 100:
                        logger.info(f"  {key}: {value[:100]}...")
                    else:
                        logger.info(f"  {key}: {value}")


def main():
    """Main validation function."""
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

    # Print database stats
    stats = client.get_database_stats()
    logger.info("\n" + "="*80)
    logger.info("DATABASE STATISTICS")
    logger.info("="*80)
    for key, value in stats.items():
        logger.info(f"{key}: {value}")

    # Create validator
    validator = DataValidator(client)

    # Print sample data
    validator.print_sample_data()

    # Parse source files
    logger.info("\n" + "="*80)
    logger.info("PARSING SOURCE FILES")
    logger.info("="*80)

    # Parse SWC
    swc_parser = SWCParser(config.SWC_DIR)
    parsed_swcs, parsed_cwes, swc_codes = swc_parser.parse_all()

    # Parse OWASP
    owasp_parser = OWASPParser(config.OWASP_SC_DIR)
    parsed_owasps, owasp_codes = owasp_parser.parse_all()

    # Parse SCSVS
    scsvs_parser = SCSVSParser(
        config.SCSVS_GENERAL_DIR,
        config.SCSVS_COMPONENTS_DIR,
        config.SCSVS_INTEGRATIONS_DIR
    )
    parsed_categories, parsed_requirements = scsvs_parser.parse_all()

    # Validate data
    swc_results = validator.validate_swc_data(parsed_swcs, parsed_cwes, swc_codes)
    owasp_results = validator.validate_owasp_data(parsed_owasps, owasp_codes)
    scsvs_results = validator.validate_scsvs_data(parsed_categories, parsed_requirements)

    # Final summary
    logger.info("\n" + "="*80)
    logger.info("FINAL VALIDATION SUMMARY")
    logger.info("="*80)
    total_issues = (
        len(swc_results['missing_swcs']) +
        len(swc_results['incomplete_swcs']) +
        len(swc_results['missing_cwes']) +
        len(owasp_results['missing_vulns']) +
        len(owasp_results['incomplete_vulns']) +
        len(scsvs_results['missing_cats']) +
        len(scsvs_results['incomplete_cats']) +
        len(scsvs_results['missing_reqs']) +
        len(scsvs_results['incomplete_reqs'])
    )

    if total_issues == 0:
        logger.info("✅ All data validated successfully! No issues found.")
    else:
        logger.warning(f"⚠️  Found {total_issues} total issues")

    # Close connection
    client.close()


if __name__ == '__main__':
    main()
