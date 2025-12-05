"""
Parser for SWC Registry markdown files.
Extracts weakness information, CWE mappings, and code examples.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import logging
import sys

# Add parent directory to path for config import
sys.path.insert(0, str(Path(__file__).parent.parent))
import config

logger = logging.getLogger(__name__)


class SWCParser:
    """Parser for SWC Registry markdown files."""

    def __init__(self, data_dir: Path):
        """
        Initialize SWC parser.

        Args:
            data_dir: Directory containing SWC markdown files
        """
        self.data_dir = data_dir

    def parse_all(self) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """
        Parse all SWC markdown files.

        Returns:
            Tuple of (swc_vulnerabilities, cwe_nodes, code_examples)
        """
        vulnerabilities = []
        cwe_nodes = {}  # Use dict to deduplicate CWE nodes
        code_examples = []

        # Find all SWC-*.md files (exclude korean directory)
        md_files = [f for f in sorted(self.data_dir.glob('SWC-*.md'))
                   if 'korean' not in str(f)]

        for md_file in md_files:
            try:
                swc, cwe, codes = self.parse_file(md_file)
                if swc:
                    vulnerabilities.append(swc)
                if cwe:
                    cwe_nodes[cwe['cwe_id']] = cwe
                code_examples.extend(codes)
            except Exception as e:
                logger.error(f"Error parsing {md_file.name}: {e}")

        logger.info(f"Parsed {len(vulnerabilities)} SWC vulnerabilities, "
                   f"{len(cwe_nodes)} unique CWE nodes, "
                   f"{len(code_examples)} code examples")

        return vulnerabilities, list(cwe_nodes.values()), code_examples

    def parse_file(self, file_path: Path) -> Tuple[Optional[Dict], Optional[Dict], List[Dict]]:
        """
        Parse a single SWC markdown file.

        Args:
            file_path: Path to markdown file

        Returns:
            Tuple of (swc_dict, cwe_dict, code_examples_list)
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Extract SWC ID from filename (e.g., SWC-107.md)
        swc_id = file_path.stem  # "SWC-107"
        swc_number = int(swc_id.split('-')[1])

        # Extract title
        title = self._extract_title(content)
        if not title:
            logger.warning(f"Could not extract title from {file_path.name}")
            return None, None, []

        # Extract CWE relationship
        cwe_node = self._extract_cwe(content)

        # Extract sections
        description = self._extract_section(content, 'Description')
        remediation = self._extract_section(content, 'Remediation')

        # Create SWC node data
        swc = {
            'swc_id': swc_id,
            'number': swc_number,
            'version': '2020',
            'title': title,
            'description': description,
            'remediation': remediation,
            'status': 'archived',
            'language': 'en',
            'type': config.DOMAIN_TYPE
        }

        # Extract code examples from Samples section
        code_examples = self._extract_samples(content, swc_id)

        return swc, cwe_node, code_examples

    def _extract_title(self, content: str) -> Optional[str]:
        """Extract title from markdown."""
        # Pattern: # Title\nTitle text
        match = re.search(r'^#\s+Title\s*\n+(.+?)$', content, re.MULTILINE)
        if match:
            return match.group(1).strip()
        return None

    def _extract_cwe(self, content: str) -> Optional[Dict]:
        """
        Extract CWE information from Relationships section.

        Args:
            content: Full markdown content

        Returns:
            CWE node dictionary or None
        """
        # Pattern: [CWE-841: Improper Enforcement...](https://cwe.mitre.org/data/definitions/841.html)
        # Support both http:// and https:// URLs
        match = re.search(
            r'\[CWE-(\d+):\s*([^\]]+)\]\((https?://cwe\.mitre\.org/data/definitions/\d+\.html)\)',
            content
        )

        if match:
            cwe_number = int(match.group(1))
            cwe_name = match.group(2).strip()
            cwe_url = match.group(3)

            return {
                'cwe_id': f"CWE-{cwe_number}",
                'number': cwe_number,
                'name': cwe_name,
                'url': cwe_url,
                'type': config.DOMAIN_TYPE
            }

        return None

    def _extract_section(self, content: str, section_name: str) -> Optional[str]:
        """
        Extract text from a markdown section.

        Args:
            content: Full markdown content
            section_name: Section header name

        Returns:
            Section text or None
        """
        # Pattern: ## Section\n\ncontent until next ##
        pattern = rf'^##\s+{re.escape(section_name)}\s*\n+(.*?)(?=\n##|\Z)'
        match = re.search(pattern, content, re.MULTILINE | re.DOTALL)

        if match:
            text = match.group(1).strip()
            # Remove code blocks
            text = re.sub(r'```[\s\S]*?```', '', text).strip()
            # Clean up
            text = re.sub(r'\n\n+', '\n\n', text)
            return text if text else None

        return None

    def _extract_samples(self, content: str, swc_id: str) -> List[Dict]:
        """
        Extract code samples from Samples section.

        Args:
            content: Full markdown content
            swc_id: SWC identifier (e.g., "SWC-107")

        Returns:
            List of code example dictionaries
        """
        code_examples = []

        # Find Samples section
        samples_match = re.search(r'^##\s+Samples\s*\n+(.*)', content, re.MULTILINE | re.DOTALL)
        if not samples_match:
            return code_examples

        samples_section = samples_match.group(1)

        # Extract individual samples
        # Pattern: ### filename.sol\n```solidity\ncode\n```
        sample_pattern = r'###\s+([\w_]+\.sol)\s*\n+```[\w]*\n(.*?)\n```'
        matches = re.finditer(sample_pattern, samples_section, re.DOTALL)

        for idx, match in enumerate(matches):
            filename = match.group(1)
            code = match.group(2).strip()

            # Determine if vulnerable or fixed based on filename
            if 'fixed' in filename.lower():
                example_type = 'fixed'
            else:
                example_type = 'vulnerable'

            example = {
                'example_id': f"swc-{swc_id.lower()}-{example_type}-{idx}",
                'example_type': example_type,
                'language': self._detect_language(code),
                'compiler_version': self._extract_compiler_version(code),
                'code': code,
                'filename': filename,
                'swc_id': swc_id,  # For linking
                'type': config.DOMAIN_TYPE
            }

            if example_type == 'vulnerable':
                example['vulnerability_pattern'] = f"Vulnerable pattern from {filename}"
            else:
                example['fix_explanation'] = f"Fixed version in {filename}"

            code_examples.append(example)

        return code_examples

    def _detect_language(self, code: str) -> str:
        """Detect programming language from code content."""
        if 'pragma solidity' in code.lower():
            return 'Solidity'
        elif 'pragma vyper' in code.lower():
            return 'Vyper'
        else:
            return 'Solidity'  # Default

    def _extract_compiler_version(self, code: str) -> Optional[str]:
        """Extract compiler version from pragma statement."""
        match = re.search(r'pragma\s+solidity\s+([\^~>=<]*\s*[\d.]+)', code, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    def get_code_relationships(self, code_examples: List[Dict]) -> List[Tuple[str, str, str, Optional[Dict]]]:
        """
        Generate relationships for code examples.

        Args:
            code_examples: List of code example dictionaries

        Returns:
            List of (from_id, to_id, rel_type, properties) tuples
        """
        relationships = []

        # Group by SWC
        swc_groups = {}
        for example in code_examples:
            swc_id = example.get('swc_id')
            if swc_id:
                if swc_id not in swc_groups:
                    swc_groups[swc_id] = {'vulnerable': [], 'fixed': []}

                if example['example_type'] == 'vulnerable':
                    swc_groups[swc_id]['vulnerable'].append(example['example_id'])
                elif example['example_type'] == 'fixed':
                    swc_groups[swc_id]['fixed'].append(example['example_id'])

        # Create relationships
        for swc_id, examples in swc_groups.items():
            # HAS_VULNERABLE_CODE: SWC -> CodeExample (vulnerable)
            for vuln_id in examples['vulnerable']:
                relationships.append((
                    swc_id,
                    vuln_id,
                    'HAS_VULNERABLE_CODE',
                    None
                ))

            # HAS_FIXED_CODE: SWC -> CodeExample (fixed)
            for fixed_id in examples['fixed']:
                relationships.append((
                    swc_id,
                    fixed_id,
                    'HAS_FIXED_CODE',
                    None
                ))

            # FIXES: CodeExample (fixed) -> CodeExample (vulnerable)
            # Match fixed to vulnerable by similar naming
            for fixed_id in examples['fixed']:
                # Try to find corresponding vulnerable example
                # Simple heuristic: match by base name
                for vuln_id in examples['vulnerable']:
                    # If both have similar base names, link them
                    if self._are_related_examples(fixed_id, vuln_id):
                        relationships.append((
                            fixed_id,
                            vuln_id,
                            'FIXES',
                            {'diff_summary': 'Fixed version of vulnerable code'}
                        ))
                        break

        return relationships

    def _are_related_examples(self, fixed_id: str, vuln_id: str) -> bool:
        """
        Determine if fixed and vulnerable examples are related.

        Simple heuristic: check if they share similar base names.
        """
        # Extract base names (remove fixed/vulnerable markers)
        fixed_base = re.sub(r'-fixed-\d+', '', fixed_id)
        vuln_base = re.sub(r'-vulnerable-\d+', '', vuln_id)

        return fixed_base == vuln_base

    def get_cwe_relationships(self, swc_vulnerabilities: List[Dict]) -> List[Tuple[str, str, str, Dict]]:
        """
        Generate MAPS_TO_CWE relationships.

        Args:
            swc_vulnerabilities: List of SWC vulnerability dictionaries

        Returns:
            List of (swc_id, cwe_id, rel_type, properties) tuples
        """
        relationships = []

        # Read files again to get CWE mappings
        md_files = [f for f in sorted(self.data_dir.glob('SWC-*.md'))
                   if 'korean' not in str(f)]

        for md_file in md_files:
            swc_id = md_file.stem

            with open(md_file, 'r', encoding='utf-8') as f:
                content = f.read()

            cwe_node = self._extract_cwe(content)
            if cwe_node:
                relationships.append((
                    swc_id,
                    cwe_node['cwe_id'],
                    'MAPS_TO_CWE',
                    {'mapping_confidence': 'direct'}
                ))

        return relationships
