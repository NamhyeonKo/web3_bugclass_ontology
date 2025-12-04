"""
Parser for SCSVS (Smart Contract Security Verification Standard) markdown files.
Extracts categories and security verification requirements.
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


class SCSVSParser:
    """Parser for SCSVS markdown files."""

    def __init__(self, general_dir: Path, components_dir: Path, integrations_dir: Path):
        """
        Initialize SCSVS parser.

        Args:
            general_dir: Directory containing General category files (G1-G12)
            components_dir: Directory containing Component category files (C1-C9)
            integrations_dir: Directory containing Integration category files (I1-I4)
        """
        self.general_dir = general_dir
        self.components_dir = components_dir
        self.integrations_dir = integrations_dir

    def parse_all(self) -> Tuple[List[Dict], List[Dict]]:
        """
        Parse all SCSVS markdown files.

        Returns:
            Tuple of (categories, requirements)
        """
        categories = []
        requirements = []

        # Parse General categories (G1-G12)
        cats, reqs = self._parse_directory(self.general_dir, 'General', 'G')
        categories.extend(cats)
        requirements.extend(reqs)

        # Parse Component categories (C1-C9)
        cats, reqs = self._parse_directory(self.components_dir, 'Component', 'C')
        categories.extend(cats)
        requirements.extend(reqs)

        # Parse Integration categories (I1-I4)
        cats, reqs = self._parse_directory(self.integrations_dir, 'Integration', 'I')
        categories.extend(cats)
        requirements.extend(reqs)

        logger.info(f"Parsed {len(categories)} SCSVS categories, "
                   f"{len(requirements)} requirements")

        return categories, requirements

    def _parse_directory(self, directory: Path, category_type: str,
                        code_prefix: str) -> Tuple[List[Dict], List[Dict]]:
        """
        Parse all markdown files in a directory.

        Args:
            directory: Directory to parse
            category_type: Type of category (General/Component/Integration)
            code_prefix: Prefix for category codes (G/C/I)

        Returns:
            Tuple of (categories, requirements)
        """
        categories = []
        requirements = []

        # Find all markdown files with pattern like 0x101-G1-*.md
        md_files = sorted(directory.glob('*.md'))

        for md_file in md_files:
            # Skip non-category files
            if not re.match(r'0x\d+-[GCI]\d+', md_file.name):
                continue

            try:
                category, reqs = self.parse_file(md_file, category_type, code_prefix)
                if category:
                    categories.append(category)
                    requirements.extend(reqs)
            except Exception as e:
                logger.error(f"Error parsing {md_file.name}: {e}")

        return categories, requirements

    def parse_file(self, file_path: Path, category_type: str,
                   code_prefix: str) -> Tuple[Optional[Dict], List[Dict]]:
        """
        Parse a single SCSVS category markdown file.

        Args:
            file_path: Path to markdown file
            category_type: Type of category
            code_prefix: Category code prefix

        Returns:
            Tuple of (category_dict, requirements_list)
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Extract category ID from filename
        # Pattern: 0x105-G5-Access-Control.md -> G5
        match = re.search(r'0x\d+-([GCI]\d+)', file_path.name)
        if not match:
            logger.warning(f"Could not extract category ID from {file_path.name}")
            return None, []

        category_id = match.group(1)

        # Extract category name from title
        # Pattern: # G5: Access control or # C1: Token
        title_match = re.search(r'^#\s+[GCI]\d+:\s+(.+)$', content, re.MULTILINE)
        if not title_match:
            logger.warning(f"Could not extract title from {file_path.name}")
            return None, []

        category_name = title_match.group(1).strip()

        # Extract control objective
        control_objective = self._extract_section(content, 'Control Objective')

        # Extract requirements table
        requirements = self._extract_requirements(content, category_id)

        # Create category node data
        category = {
            'category_id': category_id,
            'version': '2.0',
            'category_type': category_type,
            'code_prefix': code_prefix,
            'name': category_name,
            'control_objective': control_objective,
            'requirement_count': len(requirements),
            'type': config.DOMAIN_TYPE
        }

        return category, requirements

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
            # Clean up
            text = re.sub(r'\n\n+', '\n\n', text)
            return text if text else None

        return None

    def _extract_requirements(self, content: str, category_code: str) -> List[Dict]:
        """
        Extract requirements from Security Verification Requirements table.

        Args:
            content: Full markdown content
            category_code: Category code (e.g., "G5", "C1")

        Returns:
            List of requirement dictionaries
        """
        requirements = []

        # Find the requirements table section
        table_match = re.search(
            r'##\s+Security Verification Requirements\s*\n+(.*?)(?=\n##|\Z)',
            content,
            re.MULTILINE | re.DOTALL
        )

        if not table_match:
            logger.warning(f"No requirements table found for {category_code}")
            return requirements

        table_content = table_match.group(1)

        # Extract table rows
        # Pattern: | **G5.1** | Verify that ... |
        # or: | **C9.DoS.3** | Verify that ... |
        row_pattern = r'\|\s+\*\*(' + re.escape(category_code) + r'\.[\w.]+)\*\*\s+\|\s+(.+?)\s+\|'
        matches = re.finditer(row_pattern, table_content, re.MULTILINE)

        for match in matches:
            requirement_id = match.group(1)
            description = match.group(2).strip()

            # Extract number from requirement_id (e.g., "G5.1" -> "1", "C9.DoS.3" -> "DoS.3")
            number = requirement_id.split('.', 1)[1]

            # Determine if it has a sub_category (for C9.DoS.3 style IDs)
            sub_category = None
            if '.' in number:
                parts = number.split('.')
                if not parts[0].isdigit():  # If first part is not a digit, it's a sub_category
                    sub_category = parts[0]

            requirement = {
                'requirement_id': requirement_id,
                'version': '2.0',
                'category_code': category_code,
                'number': number,
                'description': description,
                'sub_category': sub_category,
                'type': config.DOMAIN_TYPE
            }

            requirements.append(requirement)

        return requirements

    def get_category_relationships(self, requirements: List[Dict]) -> List[Tuple[str, str, str, Optional[Dict]]]:
        """
        Generate HAS_REQUIREMENT relationships.

        Args:
            requirements: List of requirement dictionaries

        Returns:
            List of (category_id, requirement_id, rel_type, properties) tuples
        """
        relationships = []

        # Group requirements by category
        for idx, requirement in enumerate(requirements):
            category_id = requirement['category_code']
            requirement_id = requirement['requirement_id']

            relationships.append((
                category_id,
                requirement_id,
                'HAS_REQUIREMENT',
                {'requirement_order': idx + 1}
            ))

        return relationships
