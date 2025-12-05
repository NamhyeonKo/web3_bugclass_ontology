# Neo4j Data Validation Tests

이 디렉토리는 Neo4j에 저장된 Web3 취약점 데이터의 품질과 완전성을 검증하는 스크립트들을 포함합니다.

## 검증 스크립트

### 1. validate_neo4j_data.py

Neo4j 데이터와 원본 문서를 비교하여 데이터 완전성을 검증합니다.

**실행 방법:**
```bash
python3 tests/validate_neo4j_data.py
```

**검증 항목:**
- ✅ 모든 SWC, OWASP, SCSVS 노드의 필수 필드 존재 확인
- ✅ CWE 매핑 완전성 검증
- ✅ 코드 예제 노드 검증
- ✅ 관계 무결성 확인

**출력 예시:**
```
================================================================================
VALIDATING SWC DATA
================================================================================

📊 SWC Nodes Comparison:
  Parsed from files: 37
  Found in Neo4j: 37

📊 CWE Nodes Comparison:
  Parsed from files: 30
  Found in Neo4j: 30

✅ All SWC data validated successfully!
```

---

### 2. detailed_analysis.py

Neo4j 데이터의 상세 분석을 수행합니다.

**실행 방법:**
```bash
python3 tests/detailed_analysis.py
```

**분석 항목:**
- 📊 데이터 완전성 분석 (누락된 필드 식별)
- 📊 CWE 매핑 누락 확인
- 📊 코드 예제 통계 (타입별, 출처별)
- 📊 고아 노드 식별 (관계 없는 노드)

**출력 예시:**
```
================================================================================
SWC DATA COMPLETENESS ANALYSIS
================================================================================

Total SWC nodes: 37
Nodes with missing fields: 0
✅ All SWC nodes have complete fields

SWC nodes without CWE mapping: 0

================================================================================
CODE EXAMPLE ANALYSIS
================================================================================

Total CodeExample nodes: 138

📊 Code examples by type:
  fixed: 41
  vulnerable: 97

📊 Code examples by source:
  From SWC: 120
  From OWASP: 18
```

---

## 정기 검증 권장사항

### 데이터 업데이트 후
데이터를 새로 로드하거나 업데이트한 후 반드시 검증 스크립트를 실행하세요:

```bash
# 1. 데이터 로드
python3 scripts/main.py --clean
python3 scripts/main.py

# 2. 검증 실행
python3 tests/validate_neo4j_data.py
python3 tests/detailed_analysis.py
```

### 자동화된 검증
CI/CD 파이프라인에 검증 스크립트를 추가하여 자동으로 데이터 품질을 모니터링할 수 있습니다:

```bash
#!/bin/bash
# validate_data.sh

set -e

echo "Running data validation..."
python3 tests/validate_neo4j_data.py

echo "Running detailed analysis..."
python3 tests/detailed_analysis.py

echo "✅ All validation checks passed!"
```

---

## 검증 결과 해석

### ✅ 정상 (All data validated successfully)
모든 데이터가 원본 문서와 일치하며, 누락이나 오류가 없습니다.

### ⚠️ 경고 (Code example count mismatch)
일부 취약점에 코드 예제가 없을 수 있습니다. 이는 원본 문서에 코드 예제가 없는 경우 정상입니다.

**정상적인 누락:**
- SWC-121, SWC-122 (원본에 Samples 섹션 없음)
- SC07:2025 (Flash Loan Attacks - 해킹 사례 링크만 존재)

### ❌ 오류 (Missing nodes or fields)
데이터 누락이나 파싱 오류가 있는 경우입니다. 파서 코드를 확인하고 수정이 필요합니다.

---

## 문제 해결

### 1. 연결 오류
```
Failed to connect to Neo4j
```
- `.env` 파일에 `NEO4J_PASSWORD`가 설정되어 있는지 확인
- Neo4j 서버가 실행 중인지 확인 (`bolt://localhost:7687`)

### 2. 데이터 불일치
```
⚠️ Code example count mismatch!
```
- 원본 문서와 Neo4j 데이터를 재비교
- 파서 로직 확인 (`scripts/parsers/`)
- 데이터 재로드: `python3 scripts/main.py --clean && python3 scripts/main.py`

### 3. 파서 수정 후
파서 코드를 수정한 경우:
1. 데이터베이스 클리어: `python3 scripts/main.py --clean`
2. 데이터 재로드: `python3 scripts/main.py`
3. 검증 실행: `python3 tests/validate_neo4j_data.py`

---

## 추가 정보

- **온톨로지 스키마**: [ontology_schema.md](../ontology_schema.md)
- **메인 임포트 스크립트**: [scripts/main.py](../scripts/main.py)
- **파서 코드**: [scripts/parsers/](../scripts/parsers/)
