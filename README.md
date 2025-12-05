# Web3 Vulnerability Domain Knowledge Graph

Web3 스마트 컨트랙트 취약점에 대한 포괄적인 지식 그래프를 Neo4j로 구축하는 프로젝트입니다.

## 🎯 프로젝트 개요

이 프로젝트는 다양한 Web3 보안 표준(OWASP-SC, SWC, SCSVS)을 통합하여 하나의 지식 그래프로 구축합니다. 각 표준의 취약점을 BugClass 분류 체계로 연결하고, 코드 예제와 완화 전략을 포함합니다.

## 📊 현재 데이터 현황

### 노드 (Nodes) - 총 533개
- **VulnerabilityStandard**: 3개 (OWASP-SC, SWC, SCSVS)
- **BugClass**: 18개 (업계 표준 취약점 분류)
- **OWASP_SC**: 10개 (OWASP Smart Contract Top 10 2025)
- **SWC**: 37개 (Smart Contract Weakness Classification 2020)
- **CWE**: 30개 (MITRE Common Weakness Enumeration)
- **SCSVSCategory**: 25개 (SCSVS v2.0 카테고리)
- **SCSVSRequirement**: 272개 (검증 요구사항)
- **CodeExample**: 138개 (취약/수정 코드 예제)

### 관계 (Relationships) - 총 658개
- **BELONGS_TO_CLASS**: 72개 (취약점 → BugClass)
- **EQUIVALENT_TO**: 26개 (OWASP ↔ SWC 동등성)
- **MAPS_TO_CWE**: 37개 (SWC → CWE)
- **HAS_VULNERABLE_CODE**: 97개
- **HAS_FIXED_CODE**: 41개
- **FIXES**: 41개
- **HAS_REQUIREMENT**: 272개
- **BELONGS_TO_STANDARD**: 72개

---

## 🚀 빠른 시작

### 1. 환경 설정

```bash
# 1. 저장소 클론
git clone <repository-url>
cd web3_domain_docs

# 2. 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate  # Windows

# 3. 의존성 설치
pip install -r requirements.txt

# 4. 환경 변수 설정
cp .env.example .env
# .env 파일에서 NEO4J_PASSWORD 설정
```

### 2. Neo4j 설정

```bash
# Neo4j Desktop 또는 Docker로 Neo4j 실행
# 기본 설정:
# - URI: bolt://localhost:7687
# - Username: neo4j
# - Password: .env 파일에 설정
```

### 3. 데이터 임포트

```bash
# 단 한 줄로 모든 데이터 로드 (BugClass 포함)
python3 scripts/main.py

# 기존 데이터 삭제 후 새로 로드
python3 scripts/main.py --clean
python3 scripts/main.py
```

### 4. 데이터 검증

```bash
# 빠른 검증
python3 tests/validate_neo4j_data.py

# 상세 분석
python3 tests/detailed_analysis.py
```

---

## 📁 프로젝트 구조

```
web3_domain_docs/
├── scripts/
│   ├── main.py                    # 메인 실행 스크립트 (BugClass 포함)
│   ├── create_bug_classes.py      # BugClass 생성 및 매핑 (main.py에서 자동 호출)
│   ├── neo4j_client.py            # Neo4j 클라이언트
│   ├── config.py                  # 설정 파일
│   └── parsers/                   # 데이터 파서
│       ├── owasp_parser.py
│       ├── swc_parser.py
│       └── scsvs_parser.py
├── tests/
│   ├── validate_neo4j_data.py     # 데이터 검증
│   ├── detailed_analysis.py       # 상세 분석
│   └── README.md                  # 검증 가이드
├── OWASP-SC/                      # OWASP 원본 문서
├── SWC-registry/                  # SWC 원본 문서
├── SCSVS/                         # SCSVS 원본 문서
├── ontology_schema.md             # 온톨로지 스키마 명세
└── README.md                      # 이 파일
```

---

## 📖 사용 방법

### 기본 쿼리 예시

#### 1. BugClass별 취약점 조회
```cypher
MATCH (bc:BugClass {class_id: "BC-REENTRANCY"})
      <-[:BELONGS_TO_CLASS]-(vuln)
RETURN bc.name, labels(vuln), vuln.title
```

#### 2. OWASP와 동등한 SWC 찾기
```cypher
MATCH (owasp:OWASP_SC {vulnerability_id: "SC05:2025"})
      -[:EQUIVALENT_TO]->(swc:SWC)
RETURN owasp.title, swc.swc_id, swc.title
```

#### 3. 코드 예제 조회
```cypher
MATCH (vuln)-[:HAS_VULNERABLE_CODE]->(code:CodeExample)
WHERE vuln.vulnerability_id = "SC05:2025"
RETURN vuln.title, code.language, code.code
```

더 많은 쿼리 예시는 [ontology_schema.md](ontology_schema.md)를 참조하세요.

---

## 🔧 개발

### 파서 수정
파서를 수정한 경우:

```bash
# 1. 파서 코드 수정 (scripts/parsers/)
# 2. 데이터베이스 클리어 및 재로드
python3 scripts/main.py --clean
python3 scripts/main.py

# 3. 검증
python3 tests/validate_neo4j_data.py
```

### 새로운 데이터 소스 추가
1. 새 파서 작성 (`scripts/parsers/new_parser.py`)
2. `scripts/main.py`에 임포트 로직 추가
3. `ontology_schema.md` 업데이트
4. 검증 스크립트 실행

---

## 📚 문서

- **[ontology_schema.md](ontology_schema.md)**: 온톨로지 스키마 상세 명세
- **[tests/README.md](tests/README.md)**: 데이터 검증 가이드

---

# Web3 취약점 도메인 지식 그래프 구축 계획 (원본)

## 1. 도메인 지식 정보 리스트업

어떤 데이터들을 가지고, LLM 컨텍스트로 입력할 정보를 구성할건지에 대한 계획이 필요하다.

데이터를 큰 분류로 나누면 다음과 같이 정할 수 있다.

### **1. 버그 클래스/취약점 분류 체계 – KG의 뼈대**

1. [SWC Registry (Smart Contract Weakness Classification)](https://github.com/SmartContractSecurity/SWC-registry)
2. [DASP Top 10 (Decentralized Application Security Project)](https://github.com/CryptoServices/dasp/tree/master)
3. [OWASP Smart Contract Top 10](https://github.com/OWASP/www-project-smart-contract-top-10)
    1. 추가 가이드라인
        1. https://github.com/OWASP/www-project-smart-contract-security-verification-standard
        2. https://github.com/OWASP/www-project-blockchain-appsec-standard
4. [MITRE CWE](https://cwe.mitre.org/)
    1. SWC 각 항목에 parent CWE가 이미 매핑
    2. 이 패턴은 일반 소프트웨어에서 어떤 클래스에 해당하는지 추론 가능

### **2. 실전 감사 리포트 & 버그 바운티 리포트**

**추후 KG에 이어 붙일 내용 1**

1. Code4rena Audit Reports
2. [Sherlock](https://github.com/sherlock-protocol/sherlock-reports?utm_source=chatgpt.com)
3. OpenZeppelin
4. [Trail of Bits](https://github.com/trailofbits/publications/tree/master/reviews)

### **3. Best Practices / 패턴 독스**

**추후 KG에 이어 붙일 내용 2**

근데 이건 가이드에 가깝다. 즉 추후 코드 개선 사항 제시 또는 추가적으로 붙는게 맞는듯하다.

1. ConsenSys Smart Contract Security Best Practices
    1. https://github.com/ConsenSys/smart-contract-best-practices
    2. 취약점 → 권장 패턴/방어 코드 그래프 형성 가능
2. [ethereum.org](http://ethereum.org) security 가이드
    1. https://ethereum.org/ko/developers/docs/smart-contracts/security/?utm_source=chatgpt.com
3. 체인별/플랫폼별 best practice 문서

### **4. Web3 / DeFi 프로토콜 도메인 독스**

현재 해당 부분은 반영해서 넣어주고 있다. 시스템은 구현되었고, 성능 개선이 필요하다.

비즈니스 로직 취약점 등을 찾기 위해서 필요하다.

## 2. 온톨로지 진행

그래프화할 데이터의 스키마 정보가 필요하다.

버그 클래스/취약점 분류 체계를 어떻게 하나의 그래프로 담아낼 것인지 온톨로지 설계가 필요하다.

물론 여기서 온톨로지는 시멘틱 온톨로지를 의미한다.

### 온톨로지 예시 사진

버그 클래스 및 취약점 분류 체계만 적용
