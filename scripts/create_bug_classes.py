#!/usr/bin/env python3
"""
BugClass creation and automatic mapping script.
Maps OWASP-SC, SWC, and SCSVS to industry-standard bug classes based on 2024-2025 taxonomies.
"""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import config
from neo4j_client import Neo4jClient

logger = logging.getLogger(__name__)


# BugClass definitions based on 2024-2025 industry taxonomy
# Sources: OWASP Top 10 2025, OpenSCV, DeFi Hacks Report 2025
BUG_CLASSES = [
    # Critical severity
    {
        'class_id': 'BC-ACCESS-CONTROL',
        'name': 'Access Control Vulnerabilities',
        'description': 'Unauthorized access to functions or data due to improper permission checks',
        'severity': 'Critical',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-REENTRANCY',
        'name': 'Reentrancy Attacks',
        'description': 'External calls that re-enter the contract before state updates complete',
        'severity': 'Critical',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-ORACLE',
        'name': 'Oracle Manipulation',
        'description': 'Price oracle and external data feed manipulation vulnerabilities',
        'severity': 'Critical',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-FLASH-LOAN',
        'name': 'Flash Loan Attacks',
        'description': 'Exploits leveraging uncollateralized flash loan mechanisms',
        'severity': 'Critical',
        'type': config.DOMAIN_TYPE
    },

    # High severity
    {
        'class_id': 'BC-LOGIC-ERRORS',
        'name': 'Business Logic Errors',
        'description': 'Flaws in contract business logic and state management',
        'severity': 'High',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-ARITHMETIC',
        'name': 'Arithmetic Vulnerabilities',
        'description': 'Integer overflow, underflow, and other arithmetic errors',
        'severity': 'High',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-EXTERNAL-CALLS',
        'name': 'Unchecked External Calls',
        'description': 'Failures to check return values of external contract calls',
        'severity': 'High',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-GOVERNANCE',
        'name': 'Governance Vulnerabilities',
        'description': 'Flaws in DAO governance, voting, and proposal mechanisms',
        'severity': 'High',
        'type': config.DOMAIN_TYPE
    },

    # Medium severity
    {
        'class_id': 'BC-INPUT-VALIDATION',
        'name': 'Input Validation Failures',
        'description': 'Lack of proper input validation and sanitization',
        'severity': 'Medium',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-DOS',
        'name': 'Denial of Service',
        'description': 'Vulnerabilities that can cause contract unavailability',
        'severity': 'Medium',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-RANDOMNESS',
        'name': 'Weak Randomness',
        'description': 'Predictable or manipulable random number generation',
        'severity': 'Medium',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-FRONTRUNNING',
        'name': 'Transaction Ordering & Frontrunning',
        'description': 'Race conditions and transaction order dependence vulnerabilities',
        'severity': 'Medium',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-UPGRADABILITY',
        'name': 'Upgradeability Issues',
        'description': 'Vulnerabilities in proxy patterns and contract upgrades',
        'severity': 'Medium',
        'type': config.DOMAIN_TYPE
    },

    # Low severity
    {
        'class_id': 'BC-VISIBILITY',
        'name': 'Function Visibility Issues',
        'description': 'Incorrect function or state variable visibility settings',
        'severity': 'Low',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-CODE-QUALITY',
        'name': 'Code Quality Issues',
        'description': 'Code smells, naming issues, and best practice violations',
        'severity': 'Low',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-DEPRECATED',
        'name': 'Deprecated Features',
        'description': 'Use of deprecated Solidity features or patterns',
        'severity': 'Low',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-GAS-OPTIMIZATION',
        'name': 'Gas Optimization Issues',
        'description': 'Inefficient gas usage and optimization opportunities',
        'severity': 'Low',
        'type': config.DOMAIN_TYPE
    },
    {
        'class_id': 'BC-CRYPTOGRAPHY',
        'name': 'Cryptographic Vulnerabilities',
        'description': 'Weak cryptography, hash collisions, signature issues',
        'severity': 'Medium',
        'type': config.DOMAIN_TYPE
    },
]

# Direct OWASP → BugClass mapping (1:1 from OWASP Top 10)
OWASP_TO_BUGCLASS = {
    'SC01:2025': 'BC-ACCESS-CONTROL',
    'SC02:2025': 'BC-ORACLE',
    'SC03:2025': 'BC-LOGIC-ERRORS',
    'SC04:2025': 'BC-INPUT-VALIDATION',
    'SC05:2025': 'BC-REENTRANCY',
    'SC06:2025': 'BC-EXTERNAL-CALLS',
    'SC07:2025': 'BC-FLASH-LOAN',
    'SC08:2025': 'BC-ARITHMETIC',
    'SC09:2025': 'BC-RANDOMNESS',
    'SC10:2025': 'BC-DOS',
}

# SCSVS Category → BugClass mapping (based on category names and descriptions)
SCSVS_TO_BUGCLASS = {
    # General categories
    'G1': 'BC-LOGIC-ERRORS',  # Architecture, design
    'G2': 'BC-GOVERNANCE',    # Policies and procedures
    'G3': 'BC-UPGRADABILITY', # Upgradeability
    'G4': 'BC-LOGIC-ERRORS',  # Business logic
    'G5': 'BC-ACCESS-CONTROL', # Access control
    'G6': 'BC-EXTERNAL-CALLS', # Communications
    'G7': 'BC-ARITHMETIC',    # Arithmetic
    'G8': 'BC-DOS',           # Denial of service
    'G9': 'BC-FRONTRUNNING',  # Blockchain data (often related to frontrunning)
    'G10': 'BC-GAS-OPTIMIZATION', # Gas usage & limitations
    'G11': 'BC-CODE-QUALITY', # Code clarity
    'G12': 'BC-CODE-QUALITY', # Test coverage

    # Component categories
    'C1': 'BC-LOGIC-ERRORS',  # Token (business logic)
    'C2': 'BC-GOVERNANCE',    # Governance
    'C3': 'BC-ORACLE',        # Oracle
    'C4': 'BC-LOGIC-ERRORS',  # Vault
    'C5': 'BC-LOGIC-ERRORS',  # Bridge
    'C6': 'BC-LOGIC-ERRORS',  # NFT
    'C7': 'BC-LOGIC-ERRORS',  # Liquid staking
    'C8': 'BC-LOGIC-ERRORS',  # Liquidity pool
    'C9': 'BC-LOGIC-ERRORS',  # Uniswap V4 Hook

    # Integration categories
    'I1': 'BC-EXTERNAL-CALLS', # Basic integration
    'I2': 'BC-LOGIC-ERRORS',  # Token integration
    'I3': 'BC-ORACLE',        # Oracle integration
    'I4': 'BC-LOGIC-ERRORS',  # Cross-Chain
}

# CWE → BugClass mapping (for automated SWC classification via CWE)
CWE_TO_BUGCLASS = {
    # Access Control (CWE-284 family)
    'CWE-284': 'BC-ACCESS-CONTROL',
    'CWE-862': 'BC-ACCESS-CONTROL',
    'CWE-863': 'BC-ACCESS-CONTROL',
    'CWE-648': 'BC-ACCESS-CONTROL',

    # Reentrancy (CWE-841)
    'CWE-841': 'BC-REENTRANCY',

    # Arithmetic (CWE-190, CWE-191, CWE-682)
    'CWE-190': 'BC-ARITHMETIC',  # Integer Overflow
    'CWE-191': 'BC-ARITHMETIC',  # Integer Underflow
    'CWE-682': 'BC-ARITHMETIC',  # Incorrect Calculation

    # External Calls (CWE-252, CWE-703)
    'CWE-252': 'BC-EXTERNAL-CALLS',  # Unchecked Return Value
    'CWE-703': 'BC-EXTERNAL-CALLS',  # Improper Check or Handling
    'CWE-754': 'BC-EXTERNAL-CALLS',

    # DoS (CWE-400, CWE-835)
    'CWE-400': 'BC-DOS',  # Uncontrolled Resource Consumption
    'CWE-835': 'BC-DOS',  # Loop with Unreachable Exit Condition
    'CWE-834': 'BC-DOS',  # Excessive Iteration

    # Frontrunning / Race Conditions (CWE-362)
    'CWE-362': 'BC-FRONTRUNNING',  # Race Condition
    'CWE-366': 'BC-FRONTRUNNING',  # Race Condition within Thread

    # Randomness (CWE-338)
    'CWE-338': 'BC-RANDOMNESS',  # Weak PRNG

    # Cryptography (CWE-327, CWE-328)
    'CWE-327': 'BC-CRYPTOGRAPHY',  # Broken Crypto
    'CWE-328': 'BC-CRYPTOGRAPHY',  # Reversible Hash

    # Code Quality / Deprecated (CWE-477, CWE-1164)
    'CWE-477': 'BC-DEPRECATED',  # Use of Obsolete Function
    'CWE-1164': 'BC-CODE-QUALITY',
    'CWE-710': 'BC-CODE-QUALITY',  # Improper Adherence to Coding Standards

    # Visibility (CWE-710)
    'CWE-1102': 'BC-VISIBILITY',  # Reliance on Machine-Dependent Data Representation

    # Input Validation (CWE-20)
    'CWE-20': 'BC-INPUT-VALIDATION',
    'CWE-129': 'BC-INPUT-VALIDATION',  # Improper Validation of Array Index
}

# Manual SWC → BugClass overrides (for SWCs without clear CWE mapping)
SWC_TO_BUGCLASS_MANUAL = {
    'SWC-100': 'BC-VISIBILITY',  # Function Default Visibility
    'SWC-101': 'BC-ARITHMETIC',  # Integer Overflow and Underflow
    'SWC-102': 'BC-DEPRECATED',  # Outdated Compiler Version
    'SWC-103': 'BC-DEPRECATED',  # Floating Pragma
    'SWC-104': 'BC-EXTERNAL-CALLS',  # Unchecked Call Return Value
    'SWC-105': 'BC-ACCESS-CONTROL',  # Unprotected Ether Withdrawal
    'SWC-106': 'BC-ACCESS-CONTROL',  # Unprotected SELFDESTRUCT
    'SWC-107': 'BC-REENTRANCY',  # Reentrancy
    'SWC-108': 'BC-VISIBILITY',  # State Variable Default Visibility
    'SWC-109': 'BC-CODE-QUALITY',  # Uninitialized Storage Pointer
    'SWC-110': 'BC-CODE-QUALITY',  # Assert Violation
    'SWC-111': 'BC-DEPRECATED',  # Use of Deprecated Solidity Functions
    'SWC-112': 'BC-EXTERNAL-CALLS',  # Delegatecall to Untrusted Callee
    'SWC-113': 'BC-DOS',  # DoS with Failed Call
    'SWC-114': 'BC-FRONTRUNNING',  # Transaction Order Dependence
    'SWC-115': 'BC-ACCESS-CONTROL',  # Authorization through tx.origin
    'SWC-116': 'BC-RANDOMNESS',  # Block Timestamp Manipulation
    'SWC-117': 'BC-CODE-QUALITY',  # Signature Malleability
    'SWC-118': 'BC-CODE-QUALITY',  # Incorrect Constructor Name
    'SWC-119': 'BC-CODE-QUALITY',  # Shadowing State Variables
    'SWC-120': 'BC-RANDOMNESS',  # Weak Sources of Randomness
    'SWC-121': 'BC-CODE-QUALITY',  # Missing Protection against Signature Replay
    'SWC-122': 'BC-CODE-QUALITY',  # Lack of Proper Signature Verification
    'SWC-123': 'BC-INPUT-VALIDATION',  # Requirement Violation
    'SWC-124': 'BC-CODE-QUALITY',  # Write to Arbitrary Storage Location
    'SWC-125': 'BC-CODE-QUALITY',  # Incorrect Inheritance Order
    'SWC-126': 'BC-CODE-QUALITY',  # Insufficient Gas Griefing
    'SWC-127': 'BC-CRYPTOGRAPHY',  # Arbitrary Jump with Function Type Variable
    'SWC-128': 'BC-DOS',  # DoS With Block Gas Limit
    'SWC-129': 'BC-CODE-QUALITY',  # Typographical Error
    'SWC-130': 'BC-CODE-QUALITY',  # Right-To-Left-Override
    'SWC-131': 'BC-CODE-QUALITY',  # Presence of unused variables
    'SWC-132': 'BC-ARITHMETIC',  # Unexpected Ether balance
    'SWC-133': 'BC-CRYPTOGRAPHY',  # Hash Collisions With Multiple Variable Length Arguments
    'SWC-134': 'BC-CODE-QUALITY',  # Message call with hardcoded gas amount
    'SWC-135': 'BC-CODE-QUALITY',  # Code With No Effects
    'SWC-136': 'BC-CODE-QUALITY',  # Unencrypted Private Data On-Chain
}


def create_bug_classes(client: Neo4jClient):
    """Create all BugClass nodes."""
    logger.info(f"Creating {len(BUG_CLASSES)} BugClass nodes...")

    for bug_class in BUG_CLASSES:
        client.create_node(
            label='BugClass',
            properties=bug_class,
            id_property='class_id'
        )

    logger.info(f"Created {len(BUG_CLASSES)} BugClass nodes")


def map_owasp_to_bugclass(client: Neo4jClient):
    """Map OWASP-SC vulnerabilities to BugClasses."""
    logger.info("Mapping OWASP-SC to BugClass...")

    count = 0
    for owasp_id, bug_class_id in OWASP_TO_BUGCLASS.items():
        client.create_relationship(
            from_id=owasp_id,
            from_label='OWASP_SC',
            from_id_prop='vulnerability_id',
            to_id=bug_class_id,
            to_label='BugClass',
            to_id_prop='class_id',
            rel_type='BELONGS_TO_CLASS'
        )
        count += 1

    logger.info(f"Created {count} OWASP_SC → BugClass relationships")


def map_scsvs_to_bugclass(client: Neo4jClient):
    """Map SCSVS categories to BugClasses."""
    logger.info("Mapping SCSVS categories to BugClass...")

    count = 0
    for category_id, bug_class_id in SCSVS_TO_BUGCLASS.items():
        client.create_relationship(
            from_id=category_id,
            from_label='SCSVSCategory',
            from_id_prop='category_id',
            to_id=bug_class_id,
            to_label='BugClass',
            to_id_prop='class_id',
            rel_type='BELONGS_TO_CLASS'
        )
        count += 1

    logger.info(f"Created {count} SCSVSCategory → BugClass relationships")


def map_swc_to_bugclass(client: Neo4jClient):
    """
    Map SWC vulnerabilities to BugClasses using:
    1. Manual mapping (priority)
    2. CWE-based automatic mapping (fallback)
    """
    logger.info("Mapping SWC to BugClass...")

    # Get all SWC nodes with their CWE mappings
    with client.driver.session() as session:
        result = session.run("""
            MATCH (swc:SWC {type: $domain_type})
            OPTIONAL MATCH (swc)-[:MAPS_TO_CWE]->(cwe:CWE)
            RETURN swc.swc_id AS swc_id, collect(cwe.cwe_id) AS cwe_ids
        """, domain_type=config.DOMAIN_TYPE)

        swc_data = list(result)

    mapped_count = 0
    cwe_auto_count = 0
    unmapped = []

    for record in swc_data:
        swc_id = record['swc_id']
        cwe_ids = record['cwe_ids']

        # Priority 1: Manual mapping
        if swc_id in SWC_TO_BUGCLASS_MANUAL:
            bug_class_id = SWC_TO_BUGCLASS_MANUAL[swc_id]
            client.create_relationship(
                from_id=swc_id,
                from_label='SWC',
                from_id_prop='swc_id',
                to_id=bug_class_id,
                to_label='BugClass',
                to_id_prop='class_id',
                rel_type='BELONGS_TO_CLASS'
            )
            mapped_count += 1
            continue

        # Priority 2: CWE-based automatic mapping
        bug_class_found = False
        for cwe_id in cwe_ids:
            if cwe_id in CWE_TO_BUGCLASS:
                bug_class_id = CWE_TO_BUGCLASS[cwe_id]
                client.create_relationship(
                    from_id=swc_id,
                    from_label='SWC',
                    from_id_prop='swc_id',
                    to_id=bug_class_id,
                    to_label='BugClass',
                    to_id_prop='class_id',
                    rel_type='BELONGS_TO_CLASS',
                    properties={'mapping_source': 'cwe_auto', 'via_cwe': cwe_id}
                )
                cwe_auto_count += 1
                bug_class_found = True
                break

        if not bug_class_found:
            unmapped.append(swc_id)
            logger.warning(f"Could not map {swc_id} to BugClass (CWEs: {cwe_ids})")

    total = mapped_count + cwe_auto_count
    logger.info(f"Created {total} SWC → BugClass relationships")
    logger.info(f"  - Manual mappings: {mapped_count}")
    logger.info(f"  - CWE-based auto: {cwe_auto_count}")

    if unmapped:
        logger.warning(f"  - Unmapped SWCs: {len(unmapped)} - {unmapped}")


def create_equivalent_relationships(client: Neo4jClient):
    """
    Create EQUIVALENT_TO relationships between OWASP and SWC
    that belong to the same BugClass.
    """
    logger.info("Creating EQUIVALENT_TO relationships...")

    with client.driver.session() as session:
        # Find OWASP-SWC pairs in same BugClass
        result = session.run("""
            MATCH (owasp:OWASP_SC)-[:BELONGS_TO_CLASS]->(bc:BugClass)<-[:BELONGS_TO_CLASS]-(swc:SWC)
            WHERE owasp.type = $domain_type AND swc.type = $domain_type
            RETURN owasp.vulnerability_id AS owasp_id,
                   owasp.title AS owasp_title,
                   swc.swc_id AS swc_id,
                   swc.title AS swc_title,
                   bc.class_id AS bug_class
        """, domain_type=config.DOMAIN_TYPE)

        pairs = list(result)

    count = 0
    for pair in pairs:
        owasp_id = pair['owasp_id']
        swc_id = pair['swc_id']

        # Simple heuristic: check if titles have similar keywords
        owasp_title = pair['owasp_title'].lower()
        swc_title = pair['swc_title'].lower()

        # Determine equivalence type
        if any(keyword in owasp_title and keyword in swc_title
               for keyword in ['reentrancy', 'access', 'overflow', 'underflow', 'randomness']):
            equiv_type = 'exact'
            overlap = 1.0
        else:
            equiv_type = 'related'
            overlap = 0.5

        # Create bidirectional relationship
        client.create_relationship(
            from_id=owasp_id,
            from_label='OWASP_SC',
            from_id_prop='vulnerability_id',
            to_id=swc_id,
            to_label='SWC',
            to_id_prop='swc_id',
            rel_type='EQUIVALENT_TO',
            properties={
                'equivalence_type': equiv_type,
                'overlap_percentage': overlap,
                'via_bug_class': pair['bug_class']
            }
        )

        client.create_relationship(
            from_id=swc_id,
            from_label='SWC',
            from_id_prop='swc_id',
            to_id=owasp_id,
            to_label='OWASP_SC',
            to_id_prop='vulnerability_id',
            rel_type='EQUIVALENT_TO',
            properties={
                'equivalence_type': equiv_type,
                'overlap_percentage': overlap,
                'via_bug_class': pair['bug_class']
            }
        )

        count += 2  # bidirectional

    logger.info(f"Created {count} EQUIVALENT_TO relationships ({count//2} pairs)")


def print_statistics(client: Neo4jClient):
    """Print BugClass mapping statistics."""
    with client.driver.session() as session:
        stats = {}

        # Count each BugClass's members
        result = session.run("""
            MATCH (bc:BugClass {type: $domain_type})
            OPTIONAL MATCH (owasp:OWASP_SC)-[:BELONGS_TO_CLASS]->(bc)
            OPTIONAL MATCH (swc:SWC)-[:BELONGS_TO_CLASS]->(bc)
            OPTIONAL MATCH (scsvs:SCSVSCategory)-[:BELONGS_TO_CLASS]->(bc)
            RETURN bc.class_id AS class_id,
                   bc.name AS name,
                   bc.severity AS severity,
                   count(DISTINCT owasp) AS owasp_count,
                   count(DISTINCT swc) AS swc_count,
                   count(DISTINCT scsvs) AS scsvs_count
            ORDER BY severity DESC, class_id
        """, domain_type=config.DOMAIN_TYPE)

        logger.info("="*80)
        logger.info("BugClass Distribution:")
        logger.info("="*80)

        for record in result:
            class_id = record['class_id']
            name = record['name']
            owasp = record['owasp_count']
            swc = record['swc_count']
            scsvs = record['scsvs_count']
            total = owasp + swc + scsvs

            logger.info(f"{class_id:25} | Total: {total:3} (OWASP: {owasp:2}, SWC: {swc:2}, SCSVS: {scsvs:2})")

        logger.info("="*80)


def main():
    """Main execution."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info("Starting BugClass creation and mapping...")
    logger.info(f"Neo4j URI: {config.NEO4J_URI}")

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
        # Create BugClass nodes
        create_bug_classes(client)

        # Map all standards to BugClasses
        map_owasp_to_bugclass(client)
        map_scsvs_to_bugclass(client)
        map_swc_to_bugclass(client)

        # Create cross-standard relationships
        create_equivalent_relationships(client)

        # Print statistics
        print_statistics(client)

        logger.info("BugClass creation and mapping completed successfully!")

    except Exception as e:
        logger.error(f"Error during BugClass creation: {e}", exc_info=True)
        sys.exit(1)

    finally:
        client.close()


if __name__ == '__main__':
    main()
