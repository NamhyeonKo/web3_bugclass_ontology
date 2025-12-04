# Web3 Vulnerability Domain Knowledge Graph - Ontology Schema Specification

## Document Information

- **Version**: 2.0
- **Last Updated**: 2025-12-03
- **Purpose**: Neo4j 온톨로지 스키마 상세 명세서
- **Scope**: OWASP Smart Contract Top 10 (2025), SWC Registry (2020), SCSVS v2.0

---

## Table of Contents

1. [Node Type Specifications](#1-node-type-specifications)
2. [Relationship Type Specifications](#2-relationship-type-specifications)
3. [Property Value Constraints](#3-property-value-constraints)
4. [Index and Constraint Definitions](#4-index-and-constraint-definitions)
5. [Cardinality Rules](#5-cardinality-rules)
6. [Query Pattern Examples](#6-query-pattern-examples)
7. [Schema Evolution Guidelines](#7-schema-evolution-guidelines)

---

## 1. Node Type Specifications

### 1.1 VulnerabilityStandard

**Purpose**: 최상위 취약점 분류 체계를 나타내는 노드

**Label**: `:VulnerabilityStandard`

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `id` | String | Yes | 표준의 고유 식별자 | `"OWASP-SC"`, `"SWC"`, `"SCSVS"` |
| `name` | String | Yes | 표준의 전체 이름 | `"OWASP Smart Contract Top 10"` |
| `version` | String | Yes | 사용 중인 버전 | `"2025"`, `"2020"`, `"2.0"` |
| `description` | Text | No | 표준에 대한 설명 | `"Top 10 vulnerabilities in smart contracts"` |
| `status` | Enum | Yes | 표준의 유지보수 상태 | `"active"`, `"archived"` |
| `source_url` | String | No | 표준의 공식 URL | `"https://owasp.org/..."` |
| `maintainer` | String | No | 표준 유지보수 조직 | `"OWASP"`, `"SmartContractSecurity"` |
| `type` | String | Yes | 도메인 타입 (지식 그래프 구분용) | `"web3_vulnerability"` |

**Constraints**:
- `id` must be unique
- `status` values: `["active", "archived"]`
- `version` required for tracking which version is in use

**Example Cypher**:
```cypher
CREATE (vs:VulnerabilityStandard {
  id: "OWASP-SC",
  name: "OWASP Smart Contract Top 10",
  version: "2025",
  description: "The top 10 most critical smart contract vulnerabilities",
  status: "active",
  source_url: "https://github.com/OWASP/www-project-smart-contract-top-10",
  maintainer: "OWASP"
})
```

---

### 1.2 BugClass

**Purpose**: 큰 취약점 분류 카테고리를 나타내는 노드 (OWASP-SC Top 10처럼 상위 분류)

**Label**: `:BugClass`

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `class_id` | String | Yes | 카테고리 고유 식별자 | `"reentrancy"`, `"access-control"` |
| `name` | String | Yes | 카테고리 이름 | `"Reentrancy Attacks"`, `"Access Control Vulnerabilities"` |
| `description` | Text | No | 카테고리 설명 | `"Vulnerabilities related to reentrancy patterns..."` |
| `severity` | Enum | No | 일반적인 심각도 | `"Critical"`, `"High"`, `"Medium"`, `"Low"` |

**Constraints**:
- `class_id` must be unique
- `severity` values: `["Critical", "High", "Medium", "Low"]`

**Example Cypher**:
```cypher
CREATE (bc:BugClass {
  class_id: "reentrancy",
  name: "Reentrancy Attacks",
  description: "Vulnerabilities where external contract calls can re-enter the calling contract before state changes are finalized",
  severity: "Critical"
})
```

---

### 1.3 OWASP_SC

**Purpose**: OWASP Smart Contract Top 10의 개별 취약점 노드

**Label**: `:OWASP_SC`

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `vulnerability_id` | String | Yes | 취약점 고유 ID (버전 포함) | `"SC02:2025"` |
| `code` | String | Yes | 취약점 코드 | `"SC02"` |
| `version` | String | Yes | OWASP-SC 버전 | `"2025"` |
| `title` | String | Yes | 취약점 제목 | `"Price Oracle Manipulation"` |
| `description` | Text | Yes | 취약점 상세 설명 | `"Attackers manipulate price oracles..."` |
| `impact` | Text | No | 취약점의 영향 | `"Loss of funds, protocol insolvency"` |
| `remediation` | Text | No | 완화 및 해결 방법 | `"Use TWAP oracles, multiple oracle sources"` |
| `rank` | Integer | Yes | Top 10 내 순위 | `1` to `10` |
| `financial_loss_2024` | Float | No | 2024년 해당 취약점으로 인한 총 재정 손실 (USD) | `8800000.0` |
| `incident_count_2024` | Integer | No | 2024년 해당 취약점으로 인한 사고 건수 | `15` |
| `type` | String | Yes | 도메인 타입 (지식 그래프 구분용) | `"web3_vulnerability"` |

**Constraints**:
- `vulnerability_id` must be unique
- `code` format: `"SC" + two digits` (e.g., `"SC01"`, `"SC10"`)
- `rank` range: 1-10
- `version` currently: `"2025"`

**Example Cypher**:
```cypher
CREATE (owasp:OWASP_SC {
  vulnerability_id: "SC02:2025",
  code: "SC02",
  version: "2025",
  title: "Price Oracle Manipulation",
  description: "Price oracle manipulation occurs when attackers exploit vulnerabilities...",
  impact: "Financial loss, protocol insolvency, user fund theft",
  remediation: "Implement TWAP oracles, use multiple oracle sources, validate price ranges",
  rank: 2,
  financial_loss_2024: 8800000.0,
  incident_count_2024: 12
})
```

---

### 1.4 SWC

**Purpose**: SWC Registry의 개별 취약점 노드

**Label**: `:SWC`

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `swc_id` | String | Yes | SWC 고유 식별자 | `"SWC-107"`, `"SWC-101"` |
| `number` | Integer | Yes | SWC 번호 | `107`, `101` |
| `version` | String | Yes | SWC 버전 (아카이브 연도) | `"2020"` |
| `title` | String | Yes | 취약점 제목 | `"Reentrancy"`, `"Integer Overflow"` |
| `description` | Text | Yes | 취약점 설명 | `"One of the major dangers of calling external contracts..."` |
| `remediation` | Text | No | 완화 방법 | `"Use ReentrancyGuard modifier"` |
| `status` | String | Yes | 현재 상태 | `"archived"` |
| `language` | String | Yes | 문서 언어 | `"en"`, `"ko"` |
| `type` | String | Yes | 도메인 타입 (지식 그래프 구분용) | `"web3_vulnerability"` |

**Constraints**:
- `swc_id` must be unique
- `swc_id` format: `"SWC-" + number` (e.g., `"SWC-107"`)
- `language` values: ISO 639-1 codes (`"en"`, `"ko"`)
- `version` currently: `"2020"`

**Example Cypher**:
```cypher
CREATE (swc:SWC {
  swc_id: "SWC-107",
  number: 107,
  version: "2020",
  title: "Reentrancy",
  description: "One of the major dangers of calling external contracts is that they can take over the control flow...",
  remediation: "Make sure all internal state changes are performed before the call is executed",
  status: "archived",
  language: "en"
})
```

---

### 1.5 CWE

**Purpose**: MITRE CWE(Common Weakness Enumeration) 노드

**Label**: `:CWE`

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `cwe_id` | String | Yes | CWE 고유 식별자 | `"CWE-841"`, `"CWE-682"` |
| `number` | Integer | Yes | CWE 번호 | `841`, `682` |
| `name` | String | Yes | CWE 이름 | `"Improper Enforcement of Behavioral Workflow"` |
| `description` | Text | No | CWE 설명 | `"The software supports a session in which more than one behavior..."` |
| `abstraction_level` | Enum | No | CWE 추상화 수준 | `"Base"`, `"Class"`, `"Variant"` |
| `url` | String | No | MITRE CWE 공식 URL | `"https://cwe.mitre.org/data/definitions/841.html"` |
| `type` | String | Yes | 도메인 타입 (지식 그래프 구분용) | `"web3_vulnerability"` |

**Constraints**:
- `cwe_id` must be unique
- `cwe_id` format: `"CWE-" + number`
- `abstraction_level` values: `["Base", "Class", "Variant", "Pillar", "Category"]`

**Example Cypher**:
```cypher
CREATE (cwe:CWE {
  cwe_id: "CWE-841",
  number: 841,
  name: "Improper Enforcement of Behavioral Workflow",
  description: "The software supports a session in which more than one behavior must be performed...",
  abstraction_level: "Base",
  url: "https://cwe.mitre.org/data/definitions/841.html"
})
```

---

### 1.6 SCSVSCategory

**Purpose**: SCSVS 카테고리 노드 (G1-G12, C1-C9, I1-I4)

**Label**: `:SCSVSCategory`

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `category_id` | String | Yes | 카테고리 고유 식별자 | `"G5"`, `"C1"`, `"I1"` |
| `version` | String | Yes | SCSVS 버전 | `"2.0"` |
| `category_type` | Enum | Yes | 카테고리 타입 | `"General"`, `"Component"`, `"Integration"` |
| `code_prefix` | String | Yes | 카테고리 코드 접두사 | `"G"`, `"C"`, `"I"` |
| `name` | String | Yes | 카테고리 이름 | `"Access Control"`, `"Token"`, `"Oracle"` |
| `control_objective` | Text | No | 제어 목표 설명 | `"Access control is the process of granting or denying..."` |
| `scope` | Text | No | 카테고리 범위 설명 | `"Applies to all smart contracts with access control"` |
| `requirement_count` | Integer | No | 카테고리 내 요구사항 수 | `10`, `44` |
| `type` | String | Yes | 도메인 타입 (지식 그래프 구분용) | `"web3_vulnerability"` |

**Constraints**:
- `category_id` must be unique
- `category_type` values: `["General", "Component", "Integration"]`
- `code_prefix` values: `["G", "C", "I"]`
- `version` currently: `"2.0"`

**Note**: Component 타입 카테고리(C1-C9)의 `name`은 DeFi 컴포넌트 이름을 직접 나타냄 (예: C1 = "Token", C3 = "Oracle")

**Example Cypher**:
```cypher
CREATE (cat:SCSVSCategory {
  category_id: "C1",
  version: "2.0",
  category_type: "Component",
  code_prefix: "C",
  name: "Token",
  control_objective: "If a project contains a Token smart contract...",
  requirement_count: 9
})
```

---

### 1.7 SCSVSRequirement

**Purpose**: SCSVS 개별 검증 요구사항 노드

**Label**: `:SCSVSRequirement`

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `requirement_id` | String | Yes | 요구사항 고유 식별자 | `"G5.1"`, `"C9.DoS.3"`, `"I1.2"` |
| `version` | String | Yes | SCSVS 버전 | `"2.0"` |
| `category_code` | String | Yes | 소속 카테고리 코드 | `"G5"`, `"C9"`, `"I1"` |
| `number` | String | Yes | 카테고리 내 번호 | `"1"`, `"DoS.3"`, `"2"` |
| `description` | Text | Yes | 요구사항 설명 | `"Verify that the principle of the least privilege exists..."` |
| `sub_category` | String | No | 하위 카테고리 (C9 등) | `"DoS"`, `"Governance"`, `null` |
| `is_critical` | Boolean | No | 중요 요구사항 여부 | `true`, `false` |
| `verification_level` | Enum | No | 검증 레벨 (해당 시) | `"L1"`, `"L2"`, `"L3"` |
| `type` | String | Yes | 도메인 타입 (지식 그래프 구분용) | `"web3_vulnerability"` |

**Constraints**:
- `requirement_id` must be unique
- `requirement_id` format: `category_code + "." + number`
- `verification_level` values: `["L1", "L2", "L3"]`
- `version` currently: `"2.0"`

**Example Cypher**:
```cypher
CREATE (req:SCSVSRequirement {
  requirement_id: "C9.DoS.3",
  version: "2.0",
  category_code: "C9",
  number: "DoS.3",
  description: "Verify that the hook contract handles gas limit edge cases properly",
  sub_category: "DoS",
  is_critical: true
})
```

---

### 1.8 CodeExample

**Purpose**: 취약 코드 및 수정된 코드 예시 노드

**Label**: `:CodeExample`

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `example_id` | String | Yes | 코드 예시 고유 식별자 | `"swc107-vuln-simple-dao"` |
| `example_type` | Enum | Yes | 코드 예시 타입 | `"vulnerable"`, `"fixed"`, `"test_case"` |
| `language` | String | Yes | 프로그래밍 언어 | `"Solidity"`, `"Vyper"` |
| `compiler_version` | String | No | 컴파일러 버전 | `"^0.8.0"`, `"0.4.24"` |
| `code` | Text | Yes | 실제 코드 내용 | `"pragma solidity 0.4.24;..."` |
| `filename` | String | No | 파일명 | `"simple_dao.sol"`, `"reentrancy_fixed.sol"` |
| `lines_of_code` | Integer | No | 코드 라인 수 | `16`, `42` |
| `vulnerability_pattern` | String | No | 취약점 패턴 설명 (vulnerable 타입) | `"External call before state change"` |
| `fix_explanation` | Text | No | 수정 설명 (fixed 타입) | `"State change moved before external call"` |
| `type` | String | Yes | 도메인 타입 (지식 그래프 구분용) | `"web3_vulnerability"` |

**Constraints**:
- `example_id` must be unique
- `example_type` values: `["vulnerable", "fixed", "test_case"]`
- `language` common values: `["Solidity", "Vyper", "Cairo"]`

**Example Cypher**:
```cypher
CREATE (code:CodeExample {
  example_id: "swc107-vuln-simple-dao",
  type: "vulnerable",
  language: "Solidity",
  compiler_version: "0.4.24",
  code: "pragma solidity 0.4.24;\n\ncontract SimpleDAO {\n  mapping (address => uint) public credit;\n  ...",
  filename: "simple_dao.sol",
  lines_of_code: 16,
  vulnerability_pattern: "External call executed before state change (credit[msg.sender]-=amount)"
})
```

---

### 1.9 MitigationPattern

**Purpose**: 완화 및 방어 패턴 노드

**Label**: `:MitigationPattern`

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `pattern_id` | String | Yes | 패턴 고유 식별자 | `"mp-reentrancy-guard"` |
| `name` | String | Yes | 패턴 이름 | `"ReentrancyGuard"`, `"TWAP Oracle"` |
| `description` | Text | Yes | 패턴 설명 | `"Modifier that prevents reentrant calls to a function"` |
| `implementation_complexity` | Enum | No | 구현 복잡도 | `"Low"`, `"Medium"`, `"High"` |
| `effectiveness` | Float | No | 효과성 점수 (0.0-1.0) | `1.0`, `0.8` |
| `code_template` | Text | No | 코드 템플릿 (선택) | `"modifier nonReentrant() { require(!_locked); ... }"` |
| `library` | String | No | 관련 라이브러리 | `"OpenZeppelin"`, `"Solmate"` |

**Constraints**:
- `pattern_id` must be unique
- `implementation_complexity` values: `["Low", "Medium", "High"]`
- `effectiveness` range: 0.0-1.0

**Example Cypher**:
```cypher
CREATE (pattern:MitigationPattern {
  pattern_id: "mp-reentrancy-guard",
  name: "ReentrancyGuard",
  description: "A modifier that prevents reentrant calls to a function by using a mutex lock",
  implementation_complexity: "Low",
  effectiveness: 1.0,
  code_template: "modifier nonReentrant() { require(!_locked); _locked = true; _; _locked = false; }",
  library: "OpenZeppelin"
})
```

---

## 2. Relationship Type Specifications

### 2.1 BELONGS_TO_STANDARD

**Purpose**: 취약점/카테고리가 특정 VulnerabilityStandard에 속함을 나타냄

**Direction**: `OWASP_SC`/`SWC`/`SCSVSCategory` → `VulnerabilityStandard`

**Cardinality**: Many-to-One (여러 노드가 하나의 표준에 속함)

**Properties**: None

**Example Cypher**:
```cypher
MATCH (owasp:OWASP_SC {vulnerability_id: "SC05:2025"})
MATCH (vs:VulnerabilityStandard {id: "OWASP-SC"})
CREATE (owasp)-[:BELONGS_TO_STANDARD]->(vs)

MATCH (swc:SWC {swc_id: "SWC-107"})
MATCH (vs:VulnerabilityStandard {id: "SWC"})
CREATE (swc)-[:BELONGS_TO_STANDARD]->(vs)

MATCH (cat:SCSVSCategory {category_id: "G5"})
MATCH (vs:VulnerabilityStandard {id: "SCSVS"})
CREATE (cat)-[:BELONGS_TO_STANDARD]->(vs)
```

**Inverse Relationship**: None

---

### 2.2 BELONGS_TO_CLASS

**Purpose**: 취약점이 특정 BugClass에 속함을 나타냄

**Direction**: `OWASP_SC`/`SWC` → `BugClass`

**Cardinality**: Many-to-One (여러 취약점이 하나의 클래스에 속함)

**Properties**: None

**Example Cypher**:
```cypher
MATCH (owasp:OWASP_SC {vulnerability_id: "SC05:2025"})
MATCH (bc:BugClass {class_id: "reentrancy"})
CREATE (owasp)-[:BELONGS_TO_CLASS]->(bc)

MATCH (swc:SWC {swc_id: "SWC-107"})
MATCH (bc:BugClass {class_id: "reentrancy"})
CREATE (swc)-[:BELONGS_TO_CLASS]->(bc)
```

**Inverse Relationship**: None

---

### 2.3 MAPS_TO_CWE

**Purpose**: SWC 취약점이 CWE 항목에 매핑됨을 나타냄

**Direction**: `SWC` → `CWE`

**Cardinality**: Many-to-One (여러 SWC가 하나의 CWE에 매핑 가능)

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `mapping_confidence` | Enum | No | 매핑 신뢰도 | `"direct"`, `"related"`, `"indirect"` |

**Example Cypher**:
```cypher
MATCH (swc:SWC {swc_id: "SWC-107"})
MATCH (cwe:CWE {cwe_id: "CWE-841"})
CREATE (swc)-[:MAPS_TO_CWE {mapping_confidence: "direct"}]->(cwe)
```

**Inverse Relationship**: None

---

### 2.4 EQUIVALENT_TO

**Purpose**: 서로 다른 표준의 취약점이 동등함을 나타냄 (양방향)

**Direction**: `OWASP_SC` ↔ `SWC` (bidirectional)

**Cardinality**: Many-to-Many

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `equivalence_type` | Enum | No | 동등성 타입 | `"exact"`, `"partial"`, `"related"` |
| `overlap_percentage` | Float | No | 중첩 정도 (0.0-1.0) | `1.0`, `0.7` |
| `notes` | Text | No | 추가 설명 | `"Both cover reentrancy attacks"` |

**Example Cypher**:
```cypher
MATCH (owasp:OWASP_SC {vulnerability_id: "SC05:2025"})
MATCH (swc:SWC {swc_id: "SWC-107"})
CREATE (owasp)-[:EQUIVALENT_TO {
  equivalence_type: "exact",
  overlap_percentage: 1.0,
  notes: "Both describe reentrancy vulnerabilities"
}]->(swc)
CREATE (swc)-[:EQUIVALENT_TO {
  equivalence_type: "exact",
  overlap_percentage: 1.0
}]->(owasp)
```

**Inverse Relationship**: Symmetric (양방향 관계)

---

### 2.5 HAS_REQUIREMENT

**Purpose**: SCSVS 카테고리가 특정 요구사항을 포함함을 나타냄

**Direction**: `SCSVSCategory` → `SCSVSRequirement`

**Cardinality**: One-to-Many

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `requirement_order` | Integer | No | 카테고리 내 요구사항 순서 | `1`, `8`, `44` |

**Example Cypher**:
```cypher
MATCH (cat:SCSVSCategory {category_id: "G5"})
MATCH (req:SCSVSRequirement {requirement_id: "G5.1"})
CREATE (cat)-[:HAS_REQUIREMENT {requirement_order: 1}]->(req)
```

**Inverse Relationship**: None

---

### 2.6 RELATED_TO_GENERAL

**Purpose**: Component/Integration 카테고리가 General 카테고리와 관련됨을 나타냄

**Direction**: `SCSVSCategory` (Component/Integration) → `SCSVSCategory` (General)

**Cardinality**: Many-to-Many

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `relationship_type` | String | No | 관계 타입 | `"extends"`, `"specializes"`, `"depends_on"` |

**Example Cypher**:
```cypher
MATCH (c1:SCSVSCategory {category_id: "C1"})
MATCH (g5:SCSVSCategory {category_id: "G5"})
CREATE (c1)-[:RELATED_TO_GENERAL {relationship_type: "specializes"}]->(g5)
```

**Inverse Relationship**: None

---

### 2.7 HAS_VULNERABLE_CODE

**Purpose**: 취약점이 취약한 코드 예시를 가짐을 나타냄

**Direction**: `OWASP_SC`/`SWC` → `CodeExample` (type="vulnerable")

**Cardinality**: One-to-Many

**Properties**: None

**Example Cypher**:
```cypher
MATCH (swc:SWC {swc_id: "SWC-107"})
MATCH (code:CodeExample {example_id: "swc107-vuln-simple-dao", type: "vulnerable"})
CREATE (swc)-[:HAS_VULNERABLE_CODE]->(code)
```

**Inverse Relationship**: None

---

### 2.8 HAS_FIXED_CODE

**Purpose**: 취약점이 수정된 코드 예시를 가짐을 나타냄

**Direction**: `OWASP_SC`/`SWC` → `CodeExample` (type="fixed")

**Cardinality**: One-to-Many

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `fix_type` | Enum | No | 수정 방법 타입 | `"pattern"`, `"library"`, `"refactor"` |

**Example Cypher**:
```cypher
MATCH (swc:SWC {swc_id: "SWC-107"})
MATCH (code:CodeExample {example_id: "swc107-fixed-simple-dao", type: "fixed"})
CREATE (swc)-[:HAS_FIXED_CODE {fix_type: "pattern"}]->(code)
```

**Inverse Relationship**: None

---

### 2.9 FIXES

**Purpose**: 수정된 코드가 특정 취약한 코드를 수정함을 나타냄

**Direction**: `CodeExample` (fixed) → `CodeExample` (vulnerable)

**Cardinality**: One-to-One or Many-to-One

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `diff_summary` | Text | No | 주요 변경 사항 요약 | `"Moved state change before external call"` |
| `lines_changed` | Integer | No | 변경된 라인 수 | `3`, `15` |

**Example Cypher**:
```cypher
MATCH (fixed:CodeExample {example_id: "swc107-fixed-simple-dao"})
MATCH (vuln:CodeExample {example_id: "swc107-vuln-simple-dao"})
CREATE (fixed)-[:FIXES {
  diff_summary: "credit[msg.sender]-=amount moved before msg.sender.call.value(amount)()",
  lines_changed: 2
}]->(vuln)
```

**Inverse Relationship**: `FIXED_BY` (optional reverse direction)

---

### 2.10 MITIGATED_BY

**Purpose**: 취약점이 특정 완화 패턴으로 완화됨을 나타냄

**Direction**: `OWASP_SC`/`SWC` → `MitigationPattern`

**Cardinality**: Many-to-Many

**Properties**:

| Property | Type | Required | Description | Example |
|----------|------|----------|-------------|---------|
| `effectiveness` | Enum | No | 완화 효과성 | `"complete"`, `"partial"`, `"complementary"` |
| `priority` | Integer | No | 우선순위 (1=highest) | `1`, `2`, `3` |

**Example Cypher**:
```cypher
MATCH (owasp:OWASP_SC {vulnerability_id: "SC05:2025"})
MATCH (pattern:MitigationPattern {pattern_id: "mp-reentrancy-guard"})
CREATE (owasp)-[:MITIGATED_BY {
  effectiveness: "complete",
  priority: 1
}]->(pattern)
```

**Inverse Relationship**: `PREVENTS` (optional reverse direction)

---

## 3. Property Value Constraints

### 3.1 Enum Type Definitions

**VulnerabilityStandard.status**:
- Allowed values: `["active", "archived"]`
- Default: `"active"`

**BugClass.severity**:
- Allowed values: `["Critical", "High", "Medium", "Low"]`
- No default

**SCSVSCategory.category_type**:
- Allowed values: `["General", "Component", "Integration"]`
- No default

**CodeExample.type**:
- Allowed values: `["vulnerable", "fixed", "test_case"]`
- No default

**MitigationPattern.implementation_complexity**:
- Allowed values: `["Low", "Medium", "High"]`
- Default: `"Medium"`

**CWE.abstraction_level**:
- Allowed values: `["Base", "Class", "Variant", "Pillar", "Category"]`
- No default

**MITIGATED_BY.effectiveness**:
- Allowed values: `["complete", "partial", "complementary"]`
- Default: `"partial"`

**EQUIVALENT_TO.equivalence_type**:
- Allowed values: `["exact", "partial", "related"]`
- Default: `"related"`

**MAPS_TO_CWE.mapping_confidence**:
- Allowed values: `["direct", "related", "indirect"]`
- Default: `"direct"`

---

### 3.2 String Format Constraints

**OWASP_SC.vulnerability_id**:
- Format: `"SC" + two_digits + ":" + year`
- Regex: `^SC\d{2}:\d{4}$`
- Example: `"SC02:2025"`, `"SC10:2025"`

**SWC.swc_id**:
- Format: `"SWC-" + number`
- Regex: `^SWC-\d+$`
- Example: `"SWC-107"`, `"SWC-101"`

**CWE.cwe_id**:
- Format: `"CWE-" + number`
- Regex: `^CWE-\d+$`
- Example: `"CWE-841"`, `"CWE-682"`

**SCSVSCategory.category_id**:
- Format: `code_prefix + number`
- Regex: `^[GCI]\d+$`
- Example: `"G5"`, `"C1"`, `"I2"`

**SCSVSRequirement.requirement_id**:
- Format: `category_code + "." + number_or_subcategory`
- Regex: `^[GCI]\d+\.\w+(\.\d+)?$`
- Example: `"G5.1"`, `"C9.DoS.3"`, `"I1.2"`

**BugClass.class_id**:
- Format: lowercase with hyphens
- Regex: `^[a-z][a-z0-9-]*$`
- Example: `"reentrancy"`, `"access-control"`, `"oracle-manipulation"`

---

### 3.3 Numeric Range Constraints

**OWASP_SC.rank**:
- Range: 1-10 (inclusive)

**MitigationPattern.effectiveness**:
- Range: 0.0-1.0 (inclusive)

**EQUIVALENT_TO.overlap_percentage**:
- Range: 0.0-1.0 (inclusive)

**MITIGATED_BY.priority**:
- Range: 1-N (1 is highest priority)

---

### 3.4 Version Constraints

**VulnerabilityStandard.version**:
- OWASP-SC: `"2025"`
- SWC: `"2020"`
- SCSVS: `"2.0"`

**OWASP_SC.version**:
- Fixed value: `"2025"`

**SWC.version**:
- Fixed value: `"2020"`

**SCSVSCategory.version** and **SCSVSRequirement.version**:
- Fixed value: `"2.0"`

---

## 4. Index and Constraint Definitions

### 4.1 Uniqueness Constraints

```cypher
// VulnerabilityStandard
CREATE CONSTRAINT constraint_vuln_standard_id
FOR (vs:VulnerabilityStandard) REQUIRE vs.id IS UNIQUE;

// BugClass
CREATE CONSTRAINT constraint_bug_class_id
FOR (bc:BugClass) REQUIRE bc.class_id IS UNIQUE;

// OWASP_SC
CREATE CONSTRAINT constraint_owasp_id
FOR (o:OWASP_SC) REQUIRE o.vulnerability_id IS UNIQUE;

// SWC
CREATE CONSTRAINT constraint_swc_id
FOR (s:SWC) REQUIRE s.swc_id IS UNIQUE;

// CWE
CREATE CONSTRAINT constraint_cwe_id
FOR (c:CWE) REQUIRE c.cwe_id IS UNIQUE;

// SCSVSCategory
CREATE CONSTRAINT constraint_scsvs_category_id
FOR (sc:SCSVSCategory) REQUIRE sc.category_id IS UNIQUE;

// SCSVSRequirement
CREATE CONSTRAINT constraint_scsvs_req_id
FOR (sr:SCSVSRequirement) REQUIRE sr.requirement_id IS UNIQUE;

// CodeExample
CREATE CONSTRAINT constraint_code_example_id
FOR (ce:CodeExample) REQUIRE ce.example_id IS UNIQUE;

// MitigationPattern
CREATE CONSTRAINT constraint_mitigation_pattern_id
FOR (mp:MitigationPattern) REQUIRE mp.pattern_id IS UNIQUE;
```

---

### 4.2 Property Existence Constraints

```cypher
// Ensure critical properties exist
CREATE CONSTRAINT constraint_vuln_standard_version
FOR (vs:VulnerabilityStandard) REQUIRE vs.version IS NOT NULL;

CREATE CONSTRAINT constraint_bug_class_name
FOR (bc:BugClass) REQUIRE bc.name IS NOT NULL;

CREATE CONSTRAINT constraint_owasp_title
FOR (o:OWASP_SC) REQUIRE o.title IS NOT NULL;

CREATE CONSTRAINT constraint_owasp_version
FOR (o:OWASP_SC) REQUIRE o.version IS NOT NULL;

CREATE CONSTRAINT constraint_swc_title
FOR (s:SWC) REQUIRE s.title IS NOT NULL;

CREATE CONSTRAINT constraint_swc_version
FOR (s:SWC) REQUIRE s.version IS NOT NULL;

CREATE CONSTRAINT constraint_scsvs_cat_name
FOR (sc:SCSVSCategory) REQUIRE sc.name IS NOT NULL;

CREATE CONSTRAINT constraint_scsvs_cat_version
FOR (sc:SCSVSCategory) REQUIRE sc.version IS NOT NULL;

CREATE CONSTRAINT constraint_scsvs_req_version
FOR (sr:SCSVSRequirement) REQUIRE sr.version IS NOT NULL;
```

---

### 4.3 Single Property Indexes

```cypher
// Primary ID lookups
CREATE INDEX idx_vuln_standard_id FOR (vs:VulnerabilityStandard) ON (vs.id);
CREATE INDEX idx_bug_class_id FOR (bc:BugClass) ON (bc.class_id);
CREATE INDEX idx_owasp_vuln_id FOR (o:OWASP_SC) ON (o.vulnerability_id);
CREATE INDEX idx_swc_id FOR (s:SWC) ON (s.swc_id);
CREATE INDEX idx_cwe_id FOR (c:CWE) ON (c.cwe_id);
CREATE INDEX idx_scsvs_category_id FOR (sc:SCSVSCategory) ON (sc.category_id);
CREATE INDEX idx_scsvs_req_id FOR (sr:SCSVSRequirement) ON (sr.requirement_id);
CREATE INDEX idx_code_example_id FOR (ce:CodeExample) ON (ce.example_id);
CREATE INDEX idx_mitigation_pattern_id FOR (mp:MitigationPattern) ON (mp.pattern_id);

// Secondary property lookups
CREATE INDEX idx_owasp_code FOR (o:OWASP_SC) ON (o.code);
CREATE INDEX idx_swc_number FOR (s:SWC) ON (s.number);
CREATE INDEX idx_cwe_number FOR (c:CWE) ON (c.number);
CREATE INDEX idx_code_type FOR (ce:CodeExample) ON (ce.type);
CREATE INDEX idx_code_language FOR (ce:CodeExample) ON (ce.language);
CREATE INDEX idx_scsvs_cat_type FOR (sc:SCSVSCategory) ON (sc.category_type);

// Version lookups
CREATE INDEX idx_owasp_version FOR (o:OWASP_SC) ON (o.version);
CREATE INDEX idx_swc_version FOR (s:SWC) ON (s.version);
CREATE INDEX idx_scsvs_cat_version FOR (sc:SCSVSCategory) ON (sc.version);
CREATE INDEX idx_scsvs_req_version FOR (sr:SCSVSRequirement) ON (sr.version);
```

---

### 4.4 Composite Indexes

```cypher
// Multi-property lookups
CREATE INDEX idx_code_type_lang FOR (ce:CodeExample) ON (ce.type, ce.language);
CREATE INDEX idx_owasp_code_rank FOR (o:OWASP_SC) ON (o.code, o.rank);
CREATE INDEX idx_owasp_version_code FOR (o:OWASP_SC) ON (o.version, o.code);
CREATE INDEX idx_scsvs_version_category FOR (sc:SCSVSCategory) ON (sc.version, sc.category_id);
```

---

### 4.5 Full-Text Search Indexes

```cypher
// Text search across vulnerability descriptions
CREATE FULLTEXT INDEX idx_vuln_text_search
FOR (n:OWASP_SC|SWC)
ON EACH [n.title, n.description, n.remediation];

// Text search across bug classes
CREATE FULLTEXT INDEX idx_bug_class_text_search
FOR (bc:BugClass)
ON EACH [bc.name, bc.description];

// Text search across SCSVS requirements
CREATE FULLTEXT INDEX idx_scsvs_req_text_search
FOR (sr:SCSVSRequirement)
ON EACH [sr.description];

// Text search across code examples
CREATE FULLTEXT INDEX idx_code_text_search
FOR (ce:CodeExample)
ON EACH [ce.code, ce.vulnerability_pattern, ce.fix_explanation];
```

---

## 5. Cardinality Rules

### 5.1 One-to-Many Relationships

| Relationship | Source | Target | Rule |
|--------------|--------|--------|------|
| `HAS_REQUIREMENT` | SCSVSCategory | SCSVSRequirement | One category has multiple requirements |
| `HAS_VULNERABLE_CODE` | OWASP_SC/SWC | CodeExample | One vulnerability can have multiple code examples |
| `HAS_FIXED_CODE` | OWASP_SC/SWC | CodeExample | One vulnerability can have multiple fixed code examples |

---

### 5.2 Many-to-One Relationships

| Relationship | Source | Target | Rule |
|--------------|--------|--------|------|
| `BELONGS_TO_CLASS` | OWASP_SC/SWC | BugClass | Multiple vulnerabilities belong to one bug class |
| `MAPS_TO_CWE` | SWC | CWE | Multiple SWC entries can map to one CWE |

---

### 5.3 Many-to-Many Relationships

| Relationship | Source | Target | Rule |
|--------------|--------|--------|------|
| `EQUIVALENT_TO` | OWASP_SC | SWC | Multiple OWASP entries can be equivalent to multiple SWC entries |
| `MITIGATED_BY` | OWASP_SC/SWC | MitigationPattern | Multiple vulnerabilities can be mitigated by multiple patterns |
| `RELATED_TO_GENERAL` | SCSVSCategory | SCSVSCategory | Component/Integration categories can relate to multiple General categories |

---

### 5.4 One-to-One Relationships

| Relationship | Source | Target | Rule |
|--------------|--------|--------|------|
| `FIXES` | CodeExample (fixed) | CodeExample (vulnerable) | One fixed code typically fixes one vulnerable code |

---

## 6. Query Pattern Examples

### 6.1 Find All Vulnerabilities in a BugClass

```cypher
MATCH (bc:BugClass {class_id: "reentrancy"})<-[:BELONGS_TO_CLASS]-(vuln)
RETURN
  bc.name AS bug_class,
  labels(vuln) AS standard,
  vuln.vulnerability_id AS id,
  vuln.title AS title,
  vuln.version AS version
ORDER BY vuln.version DESC, vuln.rank
```

---

### 6.2 Get All BugClasses with Vulnerability Counts

```cypher
MATCH (bc:BugClass)<-[:BELONGS_TO_CLASS]-(vuln)
RETURN
  bc.class_id AS class_id,
  bc.name AS name,
  bc.severity AS severity,
  count(vuln) AS vulnerability_count,
  collect(DISTINCT labels(vuln)[0]) AS standards
ORDER BY vulnerability_count DESC
```

---

### 6.3 Get Complete SCSVS v2.0 Structure

```cypher
MATCH (cat:SCSVSCategory {version: "2.0"})
OPTIONAL MATCH (cat)-[:HAS_REQUIREMENT]->(req:SCSVSRequirement)
RETURN
  cat.category_type AS type,
  cat.category_id AS id,
  cat.name AS name,
  count(req) AS requirement_count,
  collect(req.requirement_id)[0..5] AS sample_requirements
ORDER BY cat.category_id
```

---

### 6.4 Map SWC to CWE to OWASP-SC

```cypher
MATCH (swc:SWC {swc_id: "SWC-107"})-[:MAPS_TO_CWE]->(cwe:CWE)
OPTIONAL MATCH (owasp:OWASP_SC)-[:EQUIVALENT_TO]->(swc)
RETURN
  swc.swc_id AS swc,
  swc.title AS swc_title,
  swc.version AS swc_version,
  cwe.cwe_id AS cwe,
  cwe.name AS cwe_name,
  collect(DISTINCT owasp.vulnerability_id) AS owasp_equivalents
```

---

### 6.5 Compare Vulnerable vs. Fixed Code

```cypher
MATCH (vuln:OWASP_SC {vulnerability_id: "SC05:2025"})-[:HAS_VULNERABLE_CODE]->(vulnerable:CodeExample {type: "vulnerable"})
MATCH (fixed:CodeExample {type: "fixed"})-[:FIXES]->(vulnerable)
RETURN
  vulnerable.filename AS vulnerable_file,
  vulnerable.vulnerability_pattern AS pattern,
  fixed.filename AS fixed_file,
  fixed.fix_explanation AS explanation,
  vulnerable.code AS vulnerable_code,
  fixed.code AS fixed_code
```

---

### 6.6 Get DeFi Component Requirements

```cypher
MATCH (cat:SCSVSCategory {version: "2.0", category_type: "Component"})
MATCH (cat)-[:HAS_REQUIREMENT]->(req:SCSVSRequirement)
WHERE req.is_critical = true
RETURN
  cat.name AS component,
  cat.category_id AS category,
  count(req) AS critical_requirements,
  collect(req.requirement_id) AS requirements
ORDER BY critical_requirements DESC
```

---

### 6.7 Find Mitigation Patterns for a BugClass

```cypher
MATCH (bc:BugClass {class_id: "reentrancy"})<-[:BELONGS_TO_CLASS]-(vuln)
MATCH (vuln)-[:MITIGATED_BY]->(pattern:MitigationPattern)
RETURN
  bc.name AS bug_class,
  pattern.name AS mitigation,
  pattern.implementation_complexity AS complexity,
  pattern.effectiveness AS effectiveness,
  count(DISTINCT vuln) AS applicable_vulnerabilities
ORDER BY effectiveness DESC
```

---

### 6.8 Find SCSVS Component Categories Related to General Categories

```cypher
MATCH (comp:SCSVSCategory {version: "2.0", category_type: "Component"})
MATCH (comp)-[rel:RELATED_TO_GENERAL]->(gen:SCSVSCategory {category_type: "General"})
RETURN
  comp.category_id AS component_id,
  comp.name AS component_name,
  gen.category_id AS general_id,
  gen.name AS general_name,
  rel.relationship_type AS relationship
ORDER BY comp.category_id
```

---

### 6.9 Full-Text Search Across All Vulnerabilities and BugClasses

```cypher
// Search vulnerabilities
CALL db.index.fulltext.queryNodes("idx_vuln_text_search", "oracle manipulation") YIELD node, score
RETURN
  node.vulnerability_id AS id,
  labels(node) AS standard,
  node.title AS title,
  node.version AS version,
  score
ORDER BY score DESC
LIMIT 20

UNION

// Search bug classes
CALL db.index.fulltext.queryNodes("idx_bug_class_text_search", "oracle manipulation") YIELD node, score
RETURN
  node.class_id AS id,
  labels(node) AS standard,
  node.name AS title,
  null AS version,
  score
ORDER BY score DESC
LIMIT 20
```

---

### 6.10 Get All Standards with Version Info

```cypher
MATCH (vs:VulnerabilityStandard)
OPTIONAL MATCH (owasp:OWASP_SC {version: vs.version})
OPTIONAL MATCH (swc:SWC {version: vs.version})
OPTIONAL MATCH (cat:SCSVSCategory {version: vs.version})
RETURN
  vs.id AS standard,
  vs.name AS name,
  vs.version AS version,
  vs.status AS status,
  count(DISTINCT owasp) AS owasp_count,
  count(DISTINCT swc) AS swc_count,
  count(DISTINCT cat) AS scsvs_category_count
ORDER BY vs.id
```

---

## 7. Schema Evolution Guidelines

### 7.1 Adding New BugClass Categories

**Process**:
1. Define new BugClass node
2. Create BELONGS_TO_CLASS relationships from existing vulnerabilities
3. Update this specification document

**Example**:
```cypher
// 1. Create new BugClass
CREATE (bc:BugClass {
  class_id: "front-running",
  name: "Front-Running Attacks",
  description: "Vulnerabilities where attackers can observe pending transactions and execute their own transactions first",
  severity: "High"
})

// 2. Link existing vulnerabilities
MATCH (owasp:OWASP_SC)
WHERE owasp.title CONTAINS "Front-running" OR owasp.description CONTAINS "front-running"
MATCH (bc:BugClass {class_id: "front-running"})
CREATE (owasp)-[:BELONGS_TO_CLASS]->(bc)
```

---

### 7.2 Version Migration Strategy

**Current Approach**: Single version per standard stored as property

**Future Multi-Version Support**:
If you need to support multiple versions (e.g., OWASP-SC 2023 and 2025 simultaneously):

1. Keep `version` property on all nodes
2. Use version-specific IDs (already implemented for OWASP_SC: "SC02:2025")
3. Query by version filter: `WHERE node.version = "2025"`

**Example Multi-Version Query**:
```cypher
// Compare same vulnerability across hypothetical versions
MATCH (v2023:OWASP_SC {code: "SC05", version: "2023"})
MATCH (v2025:OWASP_SC {code: "SC05", version: "2025"})
RETURN
  v2023.code AS code,
  v2023.title AS title_2023,
  v2025.title AS title_2025,
  CASE
    WHEN v2023.title = v2025.title THEN "Unchanged"
    ELSE "Changed"
  END AS status
```

---

### 7.3 Adding New Node Types

**Example - Adding SecurityIncident node (future)**:
```cypher
// 1. Define node
CREATE (:SecurityIncident {
  incident_id: "rari-capital-2022",
  name: "Rari Capital Hack",
  date: date("2022-05-01"),
  financial_loss: 80000000.0
})

// 2. Create constraint
CREATE CONSTRAINT constraint_incident_id
FOR (si:SecurityIncident) REQUIRE si.incident_id IS UNIQUE;

// 3. Create relationships
MATCH (owasp:OWASP_SC {vulnerability_id: "SC05:2025"})
MATCH (incident:SecurityIncident {incident_id: "rari-capital-2022"})
CREATE (owasp)-[:EXPLOITED_BY]->(incident)
```

---

### 7.4 Deprecating Properties

**Process**:
1. Mark property as deprecated in documentation
2. Provide migration script for dependent queries
3. Remove after grace period

**Example**:
```cypher
// If deprecating a property, add a new property first
MATCH (o:OWASP_SC)
SET o.new_property = o.old_property

// Then update queries to use new_property
// After grace period, remove old_property
MATCH (o:OWASP_SC)
REMOVE o.old_property
```

---

## Appendix A: Quick Reference

### Node Labels Summary

| Label | Count (Estimated) | Description |
|-------|-------------------|-------------|
| `VulnerabilityStandard` | 3 | OWASP-SC, SWC, SCSVS |
| `BugClass` | ~20 | Major vulnerability categories (Reentrancy, Access Control, etc.) |
| `OWASP_SC` | 10 | OWASP-SC 2025 vulnerabilities |
| `SWC` | 37 | SWC-100 to SWC-136 (2020) |
| `CWE` | ~50 | Referenced by SWC |
| `SCSVSCategory` | 25 | G1-G12 + C1-C9 + I1-I4 (v2.0) |
| `SCSVSRequirement` | ~200 | All requirements across categories (v2.0) |
| `CodeExample` | ~100 | Vulnerable + Fixed examples |
| `MitigationPattern` | ~30 | Common mitigation strategies |

### Relationship Types Summary

| Relationship | Count (Estimated) | Direction |
|--------------|-------------------|-----------|
| `BELONGS_TO_STANDARD` | 
| `BELONGS_TO_CLASS` | 47 | Vuln → BugClass |
| `MAPS_TO_CWE` | 37 | SWC → CWE |
| `EQUIVALENT_TO` | ~40 | OWASP ↔ SWC |
| `HAS_REQUIREMENT` | ~200 | Category → Requirement |
| `RELATED_TO_GENERAL` | ~20 | Category → Category |
| `HAS_VULNERABLE_CODE` | ~50 | Vuln → Code |
| `HAS_FIXED_CODE` | ~50 | Vuln → Code |
| `FIXES` | ~50 | Code → Code |
| `MITIGATED_BY` | ~150 | Vuln → Pattern |

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-03 | Initial | Complete ontology specification |
| 2.0 | 2025-12-03 | Revised | Removed StandardVersion, DeFiComponent, SecurityIncident nodes; Added BugClass; Simplified version management |

---

## References

1. OWASP Smart Contract Top 10: https://github.com/OWASP/www-project-smart-contract-top-10
2. SWC Registry: https://github.com/SmartContractSecurity/SWC-registry
3. SCSVS: https://github.com/ComposableSecurity/SCSVS
4. MITRE CWE: https://cwe.mitre.org/
5. Neo4j Documentation: https://neo4j.com/docs/
