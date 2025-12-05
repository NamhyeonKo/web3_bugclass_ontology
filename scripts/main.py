#!/usr/bin/env python3
"""
Main execution script for importing Web3 vulnerability data into Neo4j.

Usage:
    python main.py [--clean] [--verbose]

Options:
    --clean: Delete all existing data before import
    --verbose: Enable verbose logging
"""

import argparse
import logging
import sys
from typing import Dict

import config
from neo4j_client import Neo4jClient
from parsers import OWASPParser, SWCParser, SCSVSParser
from create_bug_classes import (
    create_bug_classes,
    map_owasp_to_bugclass,
    map_scsvs_to_bugclass,
    map_swc_to_bugclass,
    create_equivalent_relationships,
    print_statistics as print_bugclass_statistics
)


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def create_vulnerability_standards(client: Neo4jClient):
    """Create VulnerabilityStandard nodes."""
    logger = logging.getLogger(__name__)
    logger.info("Creating VulnerabilityStandard nodes...")

    for standard in config.VULNERABILITY_STANDARDS:
        client.create_node(
            label='VulnerabilityStandard',
            properties=standard,
            id_property='id'
        )

    logger.info(f"Created {len(config.VULNERABILITY_STANDARDS)} VulnerabilityStandard nodes")


def import_owasp_data(client: Neo4jClient) -> Dict[str, int]:
    """
    Import OWASP-SC data.

    Returns:
        Dictionary with import statistics
    """
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("Importing OWASP Smart Contract Top 10 data...")

    parser = OWASPParser(config.OWASP_SC_DIR)
    vulnerabilities, code_examples = parser.parse_all()

    # Create OWASP_SC nodes
    for vuln in vulnerabilities:
        client.create_node(
            label='OWASP_SC',
            properties=vuln,
            id_property='vulnerability_id'
        )

    # Create BELONGS_TO_STANDARD relationships
    for vuln in vulnerabilities:
        client.create_relationship(
            from_id=vuln['vulnerability_id'],
            from_label='OWASP_SC',
            from_id_prop='vulnerability_id',
            to_id='OWASP-SC',
            to_label='VulnerabilityStandard',
            to_id_prop='id',
            rel_type='BELONGS_TO_STANDARD'
        )

    # Create CodeExample nodes
    for example in code_examples:
        # Remove vulnerability_id before creating node (it's only for linking)
        vuln_id = example.pop('vulnerability_id', None)
        client.create_node(
            label='CodeExample',
            properties=example,
            id_property='example_id'
        )
        # Restore for relationship creation
        if vuln_id:
            example['vulnerability_id'] = vuln_id

    # Create relationships
    relationships = parser.get_code_relationships(code_examples)
    for from_id, to_id, rel_type in relationships:
        if rel_type == 'HAS_VULNERABLE_CODE' or rel_type == 'HAS_FIXED_CODE':
            # OWASP_SC -> CodeExample
            client.create_relationship(
                from_id=from_id,
                from_label='OWASP_SC',
                from_id_prop='vulnerability_id',
                to_id=to_id,
                to_label='CodeExample',
                to_id_prop='example_id',
                rel_type=rel_type
            )
        elif rel_type == 'FIXES':
            # CodeExample (fixed) -> CodeExample (vulnerable)
            client.create_relationship(
                from_id=from_id,
                from_label='CodeExample',
                from_id_prop='example_id',
                to_id=to_id,
                to_label='CodeExample',
                to_id_prop='example_id',
                rel_type=rel_type
            )

    logger.info(f"Imported {len(vulnerabilities)} OWASP-SC vulnerabilities")
    logger.info(f"Imported {len(code_examples)} code examples")
    logger.info(f"Created {len(relationships)} relationships")

    return {
        'vulnerabilities': len(vulnerabilities),
        'code_examples': len(code_examples),
        'relationships': len(relationships)
    }


def import_swc_data(client: Neo4jClient) -> Dict[str, int]:
    """
    Import SWC Registry data.

    Returns:
        Dictionary with import statistics
    """
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("Importing SWC Registry data...")

    parser = SWCParser(config.SWC_DIR)
    vulnerabilities, cwe_nodes, code_examples = parser.parse_all()

    # Create SWC nodes
    for vuln in vulnerabilities:
        client.create_node(
            label='SWC',
            properties=vuln,
            id_property='swc_id'
        )

    # Create BELONGS_TO_STANDARD relationships for SWC
    for vuln in vulnerabilities:
        client.create_relationship(
            from_id=vuln['swc_id'],
            from_label='SWC',
            from_id_prop='swc_id',
            to_id='SWC',
            to_label='VulnerabilityStandard',
            to_id_prop='id',
            rel_type='BELONGS_TO_STANDARD'
        )

    # Create CWE nodes
    for cwe in cwe_nodes:
        client.create_node(
            label='CWE',
            properties=cwe,
            id_property='cwe_id'
        )

    # Create CodeExample nodes
    for example in code_examples:
        swc_id = example.pop('swc_id', None)
        client.create_node(
            label='CodeExample',
            properties=example,
            id_property='example_id'
        )
        if swc_id:
            example['swc_id'] = swc_id

    # Create MAPS_TO_CWE relationships
    cwe_relationships = parser.get_cwe_relationships(vulnerabilities)
    for swc_id, cwe_id, rel_type, props in cwe_relationships:
        client.create_relationship(
            from_id=swc_id,
            from_label='SWC',
            from_id_prop='swc_id',
            to_id=cwe_id,
            to_label='CWE',
            to_id_prop='cwe_id',
            rel_type=rel_type,
            properties=props
        )

    # Create code example relationships
    code_relationships = parser.get_code_relationships(code_examples)
    for from_id, to_id, rel_type, props in code_relationships:
        if rel_type == 'HAS_VULNERABLE_CODE' or rel_type == 'HAS_FIXED_CODE':
            # SWC -> CodeExample
            client.create_relationship(
                from_id=from_id,
                from_label='SWC',
                from_id_prop='swc_id',
                to_id=to_id,
                to_label='CodeExample',
                to_id_prop='example_id',
                rel_type=rel_type,
                properties=props
            )
        elif rel_type == 'FIXES':
            # CodeExample (fixed) -> CodeExample (vulnerable)
            client.create_relationship(
                from_id=from_id,
                from_label='CodeExample',
                from_id_prop='example_id',
                to_id=to_id,
                to_label='CodeExample',
                to_id_prop='example_id',
                rel_type=rel_type,
                properties=props
            )

    total_relationships = len(cwe_relationships) + len(code_relationships)

    logger.info(f"Imported {len(vulnerabilities)} SWC vulnerabilities")
    logger.info(f"Imported {len(cwe_nodes)} CWE nodes")
    logger.info(f"Imported {len(code_examples)} code examples")
    logger.info(f"Created {total_relationships} relationships")

    return {
        'vulnerabilities': len(vulnerabilities),
        'cwe_nodes': len(cwe_nodes),
        'code_examples': len(code_examples),
        'relationships': total_relationships
    }


def import_scsvs_data(client: Neo4jClient) -> Dict[str, int]:
    """
    Import SCSVS data.

    Returns:
        Dictionary with import statistics
    """
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("Importing SCSVS data...")

    parser = SCSVSParser(
        config.SCSVS_GENERAL_DIR,
        config.SCSVS_COMPONENTS_DIR,
        config.SCSVS_INTEGRATIONS_DIR
    )
    categories, requirements = parser.parse_all()

    # Create SCSVSCategory nodes
    for category in categories:
        client.create_node(
            label='SCSVSCategory',
            properties=category,
            id_property='category_id'
        )

    # Create BELONGS_TO_STANDARD relationships for SCSVSCategory
    for category in categories:
        client.create_relationship(
            from_id=category['category_id'],
            from_label='SCSVSCategory',
            from_id_prop='category_id',
            to_id='SCSVS',
            to_label='VulnerabilityStandard',
            to_id_prop='id',
            rel_type='BELONGS_TO_STANDARD'
        )

    # Create SCSVSRequirement nodes
    for requirement in requirements:
        client.create_node(
            label='SCSVSRequirement',
            properties=requirement,
            id_property='requirement_id'
        )

    # Create HAS_REQUIREMENT relationships
    relationships = parser.get_category_relationships(requirements)
    for category_id, requirement_id, rel_type, props in relationships:
        client.create_relationship(
            from_id=category_id,
            from_label='SCSVSCategory',
            from_id_prop='category_id',
            to_id=requirement_id,
            to_label='SCSVSRequirement',
            to_id_prop='requirement_id',
            rel_type=rel_type,
            properties=props
        )

    logger.info(f"Imported {len(categories)} SCSVS categories")
    logger.info(f"Imported {len(requirements)} SCSVS requirements")
    logger.info(f"Created {len(relationships)} relationships")

    return {
        'categories': len(categories),
        'requirements': len(requirements),
        'relationships': len(relationships)
    }


def print_summary(client: Neo4jClient, stats: Dict):
    """Print import summary statistics."""
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("IMPORT SUMMARY")
    logger.info("=" * 60)

    logger.info("\nImported Data:")
    logger.info(f"  OWASP-SC vulnerabilities: {stats['owasp']['vulnerabilities']}")
    logger.info(f"  SWC vulnerabilities: {stats['swc']['vulnerabilities']}")
    logger.info(f"  CWE nodes: {stats['swc']['cwe_nodes']}")
    logger.info(f"  SCSVS categories: {stats['scsvs']['categories']}")
    logger.info(f"  SCSVS requirements: {stats['scsvs']['requirements']}")
    logger.info(f"  Code examples: {stats['owasp']['code_examples'] + stats['swc']['code_examples']}")

    logger.info("\nDatabase Statistics:")
    db_stats = client.get_database_stats()

    logger.info("  Nodes:")
    for key, value in db_stats.items():
        if '_nodes' in key:
            logger.info(f"    {key}: {value}")

    logger.info("\n  Relationships:")
    for key, value in db_stats.items():
        if '_relationships' in key:
            logger.info(f"    {key}: {value}")

    logger.info("=" * 60)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Import Web3 vulnerability data into Neo4j'
    )
    parser.add_argument(
        '--clean',
        action='store_true',
        help='Delete all existing data before import'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    logger.info("Starting Neo4j data import...")
    logger.info(f"Neo4j URI: {config.NEO4J_URI}")

    # Connect to Neo4j
    try:
        client = Neo4jClient(
            uri=config.NEO4J_URI,
            username=config.NEO4J_USERNAME,
            password=config.NEO4J_PASSWORD
        )
    except Exception as e:
        logger.error(f"Failed to connect to Neo4j: {e}")
        sys.exit(1)

    try:
        # Clear database if requested
        if args.clean:
            logger.warning(f"Clearing database for domain type: {config.DOMAIN_TYPE}...")
            client.clear_database(domain_type=config.DOMAIN_TYPE)
            logger.info(f"Only nodes with type='{config.DOMAIN_TYPE}' have been deleted")
            logger.info("Other data in the database remains intact")
            sys.exit(0)

        # Create schema (constraints and indexes)
        logger.info("Creating database schema...")
        client.create_constraints()
        client.create_indexes()
        client.create_fulltext_indexes()

        # Create VulnerabilityStandard nodes
        create_vulnerability_standards(client)

        # Import data from each source
        stats = {
            'owasp': import_owasp_data(client),
            'swc': import_swc_data(client),
            'scsvs': import_scsvs_data(client)
        }

        # Create BugClass nodes and mappings
        logger.info("=" * 60)
        logger.info("Creating BugClass taxonomy and mappings...")
        create_bug_classes(client)
        map_owasp_to_bugclass(client)
        map_scsvs_to_bugclass(client)
        map_swc_to_bugclass(client)
        create_equivalent_relationships(client)
        print_bugclass_statistics(client)

        # Print summary
        print_summary(client, stats)

        logger.info("Data import completed successfully!")

    except Exception as e:
        logger.error(f"Error during import: {e}", exc_info=True)
        sys.exit(1)

    finally:
        client.close()


if __name__ == '__main__':
    main()
