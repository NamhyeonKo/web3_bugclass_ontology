# Neo4j Data Import Scripts

Python scripts for extracting Web3 vulnerability data from markdown files and importing into Neo4j database.

## Overview

These scripts parse vulnerability data from three major sources and construct a knowledge graph in Neo4j:

- **OWASP Smart Contract Top 10 (2025)**: Top 10 critical smart contract vulnerabilities
- **SWC Registry (2020)**: Smart Contract Weakness Classification with 37 entries
- **SCSVS v2.0**: Smart Contract Security Verification Standard with 200+ requirements

## Prerequisites

1. **Python 3.8+**
2. **Neo4j Database** (Version 5.0+)
   - Local installation: https://neo4j.com/download/
   - Or use Neo4j Aura (cloud): https://neo4j.com/cloud/aura/

## Installation

### 1. Install Python Dependencies

```bash
cd scripts
pip install -r requirements.txt
```

### 2. Configure Neo4j Connection

Copy the example environment file and edit with your credentials:

```bash
cp .env.example .env
```

Edit `.env` file:

```
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_actual_password
```

### 3. Verify Data Files

Ensure the following directories exist with markdown files:
- `../OWASP-SC/2025/` (10 files: SC01.md through SC10.md)
- `../SWC-registry/2020/` (37 files: SWC-100.md through SWC-136.md)
- `../SCSVS/2.0/0x100-General/` (12 files)
- `../SCSVS/2.0/0x200-Components/` (9 files)
- `../SCSVS/2.0/0x300-Integrations/` (4 files)

## Usage

### Basic Import

Import all data into Neo4j (preserves existing data):

```bash
python main.py
```

### Clean Import

Delete existing Web3 vulnerability data before importing:

```bash
python main.py --clean
```

⚠️ **Note**: The `--clean` flag will delete ONLY nodes with `type: "web3_vulnerability"`. Other data in your Neo4j database will remain intact. This allows you to safely use the same database for multiple knowledge graphs.

### Verbose Output

Enable detailed logging for debugging:

```bash
python main.py --verbose
```

### Combined Options

```bash
python main.py --clean --verbose
```

## What Gets Imported

### Node Types

All nodes include a `type: "web3_vulnerability"` property to distinguish this knowledge graph from other Neo4j data.

| Node Label | Count | Description |
|------------|-------|-------------|
| `VulnerabilityStandard` | 3 | OWASP-SC, SWC, SCSVS metadata |
| `OWASP_SC` | 10 | OWASP vulnerabilities (SC01-SC10) |
| `SWC` | 37 | SWC weaknesses (SWC-100 to SWC-136) |
| `CWE` | ~50 | MITRE CWE entries (extracted from SWC) |
| `SCSVSCategory` | 25 | SCSVS categories (G1-G12, C1-C9, I1-I4) |
| `SCSVSRequirement` | ~200 | SCSVS verification requirements |
| `CodeExample` | ~100+ | Vulnerable and fixed code examples |

### Relationship Types

| Relationship | Count | Description |
|--------------|-------|-------------|
| `HAS_REQUIREMENT` | ~200 | Category → Requirement |
| `HAS_VULNERABLE_CODE` | ~50 | Vulnerability → CodeExample (vulnerable) |
| `HAS_FIXED_CODE` | ~50 | Vulnerability → CodeExample (fixed) |
| `FIXES` | ~50 | CodeExample (fixed) → CodeExample (vulnerable) |
| `MAPS_TO_CWE` | ~37 | SWC → CWE |

## Project Structure

```
scripts/
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── .env.example             # Example configuration
├── .env                     # Your configuration (create this)
├── config.py                # Configuration loader
├── neo4j_client.py          # Neo4j connection and operations
├── main.py                  # Main execution script
└── parsers/
    ├── __init__.py
    ├── owasp_parser.py      # OWASP-SC parser
    ├── swc_parser.py        # SWC Registry parser
    └── scsvs_parser.py      # SCSVS parser
```

## Example Queries

After importing, you can query the knowledge graph:

### Find all OWASP vulnerabilities

```cypher
MATCH (o:OWASP_SC {type: "web3_vulnerability"})
RETURN o.code, o.title, o.rank
ORDER BY o.rank
```

### Find all nodes in this knowledge graph

```cypher
MATCH (n {type: "web3_vulnerability"})
RETURN labels(n)[0] AS NodeType, count(n) AS Count
ORDER BY Count DESC
```

### Get vulnerability with code examples

```cypher
MATCH (o:OWASP_SC {code: "SC05"})-[:HAS_VULNERABLE_CODE]->(vuln:CodeExample)
MATCH (o)-[:HAS_FIXED_CODE]->(fixed:CodeExample)
RETURN o.title, vuln.code AS vulnerable_code, fixed.code AS fixed_code
```

### Find SWC mapped to CWE

```cypher
MATCH (s:SWC)-[:MAPS_TO_CWE]->(c:CWE)
RETURN s.swc_id, s.title, c.cwe_id, c.name
LIMIT 10
```

### Get SCSVS category with requirements

```cypher
MATCH (cat:SCSVSCategory {category_id: "G5"})-[:HAS_REQUIREMENT]->(req:SCSVSRequirement)
RETURN cat.name, count(req) AS requirement_count,
       collect(req.requirement_id)[0..5] AS sample_requirements
```

### Search vulnerabilities by keyword

```cypher
CALL db.index.fulltext.queryNodes("idx_vuln_text_search", "reentrancy")
YIELD node, score
RETURN node.vulnerability_id, node.title, score
ORDER BY score DESC
LIMIT 10
```

## Troubleshooting

### Connection Issues

If you get connection errors:

1. Verify Neo4j is running:
   ```bash
   # For local installation
   neo4j status
   ```

2. Check connection details in `.env` file

3. Test connection in Neo4j Browser: http://localhost:7474

### Missing Data Directories

If you get `FileNotFoundError`:

```
FileNotFoundError: Required data directory not found: /path/to/OWASP-SC/2025
```

Ensure you're running the script from the correct location and all data directories exist.

### Constraint Violations

If you get constraint violation errors, run with `--clean` flag to reset the Web3 vulnerability data:

```bash
python main.py --clean
```

This will delete only the `type: "web3_vulnerability"` nodes, leaving other data untouched.

### Deleting ALL Data (Not Recommended)

If you need to delete ALL data from the database (not just Web3 vulnerability data), you can do so manually in Neo4j Browser:

```cypher
MATCH (n) DETACH DELETE n
```

⚠️ **Warning**: This will delete EVERYTHING in your database!

## Domain Isolation

All nodes created by this script include a `type: "web3_vulnerability"` property. This enables:

### 1. Multi-Domain Database Support

You can safely store multiple knowledge graphs in the same Neo4j database:

```cypher
// Web3 Vulnerability nodes
MATCH (n {type: "web3_vulnerability"})
RETURN count(n)

// Other domain nodes
MATCH (n)
WHERE n.type <> "web3_vulnerability" OR n.type IS NULL
RETURN count(n)
```

### 2. Selective Data Management

The `--clean` flag only removes Web3 vulnerability data:

```bash
# Removes ONLY web3_vulnerability nodes
python main.py --clean

# Other data remains intact
```

### 3. Scoped Queries

Filter queries to this knowledge graph:

```cypher
// All OWASP vulnerabilities (Web3 domain only)
MATCH (o:OWASP_SC {type: "web3_vulnerability"})
RETURN o

// All nodes in this domain
MATCH (n {type: "web3_vulnerability"})
RETURN labels(n)[0] AS NodeType, count(n) AS Count
ORDER BY Count DESC
```

## Schema Reference

The database schema follows the ontology defined in `../ontology_schema.md`. Key features:

- **Domain Isolation**: All nodes tagged with `type: "web3_vulnerability"`
- **Uniqueness Constraints**: Ensure no duplicate nodes
- **Indexes**: Fast lookups by ID, version, type
- **Full-Text Indexes**: Search across descriptions and code
- **Composite Indexes**: Efficient multi-property queries

## Advanced Usage

### Import Specific Data Sources

You can modify `main.py` to import only specific sources by commenting out unwanted import calls:

```python
# Import only OWASP data
stats = {
    'owasp': import_owasp_data(client),
    # 'swc': import_swc_data(client),     # Commented out
    # 'scsvs': import_scsvs_data(client)  # Commented out
}
```

### Custom Parsing

Each parser module (`parsers/*.py`) can be used independently:

```python
from parsers import OWASPParser
from pathlib import Path

parser = OWASPParser(Path('../OWASP-SC/2025'))
vulnerabilities, code_examples = parser.parse_all()

for vuln in vulnerabilities:
    print(f"{vuln['code']}: {vuln['title']}")
```

## Future Enhancements

The following features are planned for Phase 2:

- [ ] **BugClass Creation**: Automatic categorization of vulnerabilities
- [ ] **EQUIVALENT_TO Relationships**: Mapping between OWASP and SWC
- [ ] **MITIGATED_BY Relationships**: Link to mitigation patterns
- [ ] **MitigationPattern Nodes**: Security best practices and fixes
- [ ] **Incremental Updates**: Update only changed data
- [ ] **Data Validation**: Verify completeness and consistency

## Contributing

To add new parsers or enhance existing ones:

1. Follow the existing parser pattern in `parsers/`
2. Implement required methods: `parse_all()`, `parse_file()`
3. Add node creation logic to `main.py`
4. Update this README with new data types

## License

See parent directory for license information.

## References

- [OWASP Smart Contract Top 10](https://github.com/OWASP/www-project-smart-contract-top-10)
- [SWC Registry](https://github.com/SmartContractSecurity/SWC-registry)
- [SCSVS](https://github.com/ComposableSecurity/SCSVS)
- [Neo4j Documentation](https://neo4j.com/docs/)
- [Ontology Schema](../ontology_schema.md)
