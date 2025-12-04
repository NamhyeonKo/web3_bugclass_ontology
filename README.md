# Web3 취약점 도메인 지식 그래프 구축 계획

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
