"""
Parser for OWASP Smart Contract Top 10 markdown files.
Extracts vulnerability information and code examples.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import logging
import sys
from pathlib import Path

# Add parent directory to path for config import
sys.path.insert(0, str(Path(__file__).parent.parent))
import config

logger = logging.getLogger(__name__)


class OWASPParser:
    """Parser for OWASP-SC markdown files."""

    def __init__(self, data_dir: Path):
        """
        Initialize OWASP parser.

        Args:
            data_dir: Directory containing OWASP-SC markdown files
        """
        self.data_dir = data_dir

    def parse_all(self) -> Tuple[List[Dict], List[Dict]]:
        """
        Parse all OWASP-SC markdown files.

        Returns:
            Tuple of (vulnerabilities, code_examples)
        """
        vulnerabilities = []
        code_examples = []

        # Find all SC*.md files
        md_files = sorted(self.data_dir.glob('SC*.md'))

        for md_file in md_files:
            try:
                vuln, codes = self.parse_file(md_file)
                if vuln:
                    vulnerabilities.append(vuln)
                    code_examples.extend(codes)
            except Exception as e:
                logger.error(f"Error parsing {md_file.name}: {e}")

        logger.info(f"Parsed {len(vulnerabilities)} OWASP-SC vulnerabilities, "
                   f"{len(code_examples)} code examples")

        return vulnerabilities, code_examples

    def parse_file(self, file_path: Path) -> Tuple[Optional[Dict], List[Dict]]:
        """
        Parse a single OWASP-SC markdown file.

        Args:
            file_path: Path to markdown file

        Returns:
            Tuple of (vulnerability_dict, code_examples_list)
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Extract vulnerability ID and title from first header
        # Format: # SC02:2025 - Title OR ## SC01:2025 - Title OR ## SC06:2025  Title
        title_match = re.search(r'^#{1,2}\s+(SC\d{2}):(\d{4})\s+[-]?\s*(.+)$', content, re.MULTILINE)
        if not title_match:
            logger.warning(f"Could not extract title from {file_path.name}")
            return None, []

        code = title_match.group(1)
        version = title_match.group(2)
        title = title_match.group(3).strip()
        vulnerability_id = f"{code}:{version}"
        rank = int(code[2:])  # Extract number from SC01 -> 1

        # Extract sections
        description = self._extract_section(content, 'Description')
        impact = self._extract_section(content, 'Impact')
        remediation = self._extract_section(content, 'Remediation')

        # Extract code examples (try both capitalization variants)
        vulnerable_code = self._extract_code_example(content, 'Example (Vulnerable contract)')
        if not vulnerable_code:
            vulnerable_code = self._extract_code_example(content, 'Example (Vulnerable Contract)')

        fixed_code = self._extract_code_example(content, 'Example (Fixed version)')
        if not fixed_code:
            fixed_code = self._extract_code_example(content, 'Example (Fixed Version)')

        # Create vulnerability node data
        vulnerability = {
            'vulnerability_id': vulnerability_id,
            'code': code,
            'version': version,
            'title': title,
            'description': description,
            'impact': impact,
            'remediation': remediation,
            'rank': rank,
            'type': config.DOMAIN_TYPE
        }

        # Create code example nodes
        code_examples = []

        if vulnerable_code:
            vuln_example = {
                'example_id': f"owasp-{code.lower()}-vuln",
                'example_type': 'vulnerable',
                'language': self._detect_language(vulnerable_code),
                'compiler_version': self._extract_compiler_version(vulnerable_code),
                'code': vulnerable_code,
                'vulnerability_pattern': f"Vulnerable pattern in {title}",
                'vulnerability_id': vulnerability_id,  # For linking
                'type': config.DOMAIN_TYPE
            }
            code_examples.append(vuln_example)

        if fixed_code:
            fixed_example = {
                'example_id': f"owasp-{code.lower()}-fixed",
                'example_type': 'fixed',
                'language': self._detect_language(fixed_code),
                'compiler_version': self._extract_compiler_version(fixed_code),
                'code': fixed_code,
                'fix_explanation': f"Fixed version of {title}",
                'vulnerability_id': vulnerability_id,  # For linking
                'type': config.DOMAIN_TYPE
            }
            code_examples.append(fixed_example)

        return vulnerability, code_examples

    def _extract_section(self, content: str, section_name: str) -> Optional[str]:
        """
        Extract text from a markdown section.

        Args:
            content: Full markdown content
            section_name: Section header name

        Returns:
            Section text or None
        """
        # Pattern: ## or ### Section_name: (with optional space after colon) content until next header
        pattern = rf'#{{2,3}}\s+{re.escape(section_name)}:\s*\n+(.*?)(?=\n#{{1,3}}\s+[A-Z]|\Z)'
        match = re.search(pattern, content, re.DOTALL | re.MULTILINE)

        if match:
            text = match.group(1).strip()
            # Remove code blocks from description/impact/remediation
            text = re.sub(r'```[\s\S]*?```', '', text).strip()
            # Clean up bullet points and extra whitespace
            text = re.sub(r'\n+', '\n', text)
            return text if text else None

        return None

    def _extract_code_example(self, content: str, section_name: str) -> Optional[str]:
        """
        Extract code block from a section.

        Args:
            content: Full markdown content
            section_name: Section header name

        Returns:
            Code content or None
        """
        # Pattern: ## or ### Section_name:\n```\ncode\n```
        pattern = rf'#{{2,3}}\s+{re.escape(section_name)}:\s*\n+```[a-z]*\n(.*?)\n```'
        match = re.search(pattern, content, re.DOTALL)

        if match:
            return match.group(1).strip()

        return None

    def _detect_language(self, code: str) -> str:
        """
        Detect programming language from code content.

        Args:
            code: Code string

        Returns:
            Language name
        """
        if 'pragma solidity' in code.lower():
            return 'Solidity'
        elif 'pragma vyper' in code.lower():
            return 'Vyper'
        elif '#[contract]' in code or 'impl' in code:
            return 'Cairo'
        else:
            return 'Solidity'  # Default assumption

    def _extract_compiler_version(self, code: str) -> Optional[str]:
        """
        Extract compiler version from pragma statement.

        Args:
            code: Code string

        Returns:
            Compiler version or None
        """
        # Pattern: pragma solidity ^0.8.0;
        match = re.search(r'pragma\s+solidity\s+([\^~>=<]*\s*[\d.]+)', code, re.IGNORECASE)
        if match:
            return match.group(1).strip()

        return None

    def get_code_relationships(self, code_examples: List[Dict]) -> List[Tuple[str, str, str]]:
        """
        Generate relationships for code examples.

        Args:
            code_examples: List of code example dictionaries

        Returns:
            List of (from_id, to_id, rel_type) tuples
        """
        relationships = []

        # Group by vulnerability
        vuln_groups = {}
        for example in code_examples:
            vuln_id = example.get('vulnerability_id')
            if vuln_id:
                if vuln_id not in vuln_groups:
                    vuln_groups[vuln_id] = {'vulnerable': None, 'fixed': None}

                if example['example_type'] == 'vulnerable':
                    vuln_groups[vuln_id]['vulnerable'] = example['example_id']
                elif example['example_type'] == 'fixed':
                    vuln_groups[vuln_id]['fixed'] = example['example_id']

        # Create relationships
        for vuln_id, examples in vuln_groups.items():
            # HAS_VULNERABLE_CODE: OWASP_SC -> CodeExample (vulnerable)
            if examples['vulnerable']:
                relationships.append((
                    vuln_id,
                    examples['vulnerable'],
                    'HAS_VULNERABLE_CODE'
                ))

            # HAS_FIXED_CODE: OWASP_SC -> CodeExample (fixed)
            if examples['fixed']:
                relationships.append((
                    vuln_id,
                    examples['fixed'],
                    'HAS_FIXED_CODE'
                ))

            # FIXES: CodeExample (fixed) -> CodeExample (vulnerable)
            if examples['fixed'] and examples['vulnerable']:
                relationships.append((
                    examples['fixed'],
                    examples['vulnerable'],
                    'FIXES'
                ))

        return relationships
