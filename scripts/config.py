"""
Configuration module for Neo4j data import script.
Loads environment variables and defines path constants.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Neo4j connection settings
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
NEO4J_USERNAME = os.getenv('NEO4J_USERNAME', 'neo4j')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD')

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
OWASP_SC_DIR = BASE_DIR / 'OWASP-SC' / '2025'
SWC_DIR = BASE_DIR / 'SWC-registry' / '2020'
SCSVS_DIR = BASE_DIR / 'SCSVS' / '2.0'

# SCSVS subdirectories
SCSVS_GENERAL_DIR = SCSVS_DIR / '0x100-General'
SCSVS_COMPONENTS_DIR = SCSVS_DIR / '0x200-Components'
SCSVS_INTEGRATIONS_DIR = SCSVS_DIR / '0x300-Integrations'

# Domain type identifier for all nodes
DOMAIN_TYPE = 'web3_vulnerability'

# Vulnerability standards metadata
VULNERABILITY_STANDARDS = [
    {
        'id': 'OWASP-SC',
        'name': 'OWASP Smart Contract Top 10',
        'version': '2025',
        'status': 'active',
        'source_url': 'https://github.com/OWASP/www-project-smart-contract-top-10',
        'maintainer': 'OWASP',
        'description': 'The top 10 most critical smart contract vulnerabilities',
        'type': DOMAIN_TYPE
    },
    {
        'id': 'SWC',
        'name': 'Smart Contract Weakness Classification',
        'version': '2020',
        'status': 'archived',
        'source_url': 'https://github.com/SmartContractSecurity/SWC-registry',
        'maintainer': 'SmartContractSecurity',
        'description': 'Smart Contract Weakness Classification and Test Cases',
        'type': DOMAIN_TYPE
    },
    {
        'id': 'SCSVS',
        'name': 'Smart Contract Security Verification Standard',
        'version': '2.0',
        'status': 'active',
        'source_url': 'https://github.com/ComposableSecurity/SCSVS',
        'maintainer': 'ComposableSecurity',
        'description': 'Security standard for smart contract verification',
        'type': DOMAIN_TYPE
    }
]

# Validation
if not NEO4J_PASSWORD:
    raise ValueError(
        "NEO4J_PASSWORD not set. Please create a .env file with your credentials. "
        "See .env.example for reference."
    )

# Verify data directories exist
required_dirs = [OWASP_SC_DIR, SWC_DIR, SCSVS_GENERAL_DIR, SCSVS_COMPONENTS_DIR, SCSVS_INTEGRATIONS_DIR]
for directory in required_dirs:
    if not directory.exists():
        raise FileNotFoundError(f"Required data directory not found: {directory}")
