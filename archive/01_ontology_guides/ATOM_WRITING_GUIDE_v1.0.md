# GR 원자 작성 가이드 v1.0

> **목적**: 일관된 품질의 원자를 작성하기 위한 표준 가이드
> **작성일**: 2025-01-28

---

## 1. 원자(Atom)란?

```
원자 = GR 온톨로지의 최소 지식 단위

특징:
  - 하나의 명확한 개념/기법/요소를 표현
  - 다른 원자와 관계로 연결됨
  - AI 추론에 활용 가능한 구조화된 정보
  - 자체 LLM 학습에 사용 가능한 설명 포함
```

---

## 2. 원자 유형

| 유형 | ID 프리픽스 | 설명 | 예시 |
|------|-------------|------|------|
| Infrastructure | INFRA-* | 인프라 구성요소 | WAS, DB, 방화벽 |
| Attack | ATK-* | 공격 기법 | SQL Injection, XSS |
| Defense | DEF-* | 방어 기법 | WAF, 암호화 |
| Vulnerability | VUL-* | 취약점 유형 | CWE 기반 |
| Tool | TOOL-* | 도구 | Burp Suite, nmap |
| Concept | CON-* | 개념/원칙 | Zero Trust, Defense in Depth |

---

## 3. 필수 섹션

### 3.1 Identity (정체성) - 필수

```yaml
id: "INFRA-APP-WAS-001"          # 필수: 고유 ID
name: "Web Application Server"   # 필수: 정식 명칭
aliases: ["WAS", "App Server"]   # 권장: 검색용 별칭
normalized_name: "web_application_server"  # 필수: 정규화된 이름
```

**ID 규칙**:
- 형식: `{DOMAIN}-{SUBDOMAIN}-{NAME}-{###}`
- 예: `INFRA-APP-WAS-001`, `ATK-INJECT-SQL-001`
- 숫자는 001부터 순차 부여

### 3.2 Classification (분류) - 필수

```yaml
classification:
  domain: "infrastructure"       # 필수: 도메인
  type: "component"              # 필수: 유형
  abstraction_level: 2           # 필수: 추상화 수준 (1-4)

  gr_coordinates:                # 필수: GR 좌표
    layer: "L7"
    zone: "Zone2"
    function_tags: ["A-runtime", "S-session"]
```

**추상화 수준**:
- 1: Instance (특정 제품: Apache Tomcat 9.0)
- 2: Type (유형: WAS, RDBMS)
- 3: Concept (개념: 미들웨어, 데이터 저장소)
- 4: Principle (원칙: 계층화, 격리)

### 3.3 Definition (정의) - 필수

```yaml
definition:
  what: |
    [200-300자]
    이것이 무엇인가?
    핵심 특징과 역할 설명

  why: |
    [150-200자]
    왜 중요한가?
    존재 이유와 가치

  how: |
    [200-400자]
    어떻게 작동하는가?
    동작 원리나 프로세스
```

**작성 팁**:
- 전문 용어는 첫 등장 시 간단히 설명
- 비유나 예시로 이해도 향상
- LLM이 학습할 수 있도록 명확하게

### 3.4 Relations (관계) - 필수

```yaml
relations:
  # 계층 관계
  is_a:
    - id: "CON-MIDDLEWARE-001"
      name: "Middleware"

  has_subtypes:
    - id: "INFRA-APP-WAS-TOMCAT-001"
      name: "Apache Tomcat"

  # 연결 관계
  connects_to:
    - id: "INFRA-DATA-RDBMS-001"
      name: "RDBMS"
      protocol: "JDBC"
      direction: "downstream"

  # 의존 관계
  depends_on:
    - id: "INFRA-RUNTIME-JVM-001"
      name: "Java Virtual Machine"

  # 보안 관계 (유형별 선택)
  vulnerable_to:      # 인프라용
    - id: "VUL-DESER-001"

  targets:            # 공격용
    - id: "INFRA-APP-WAS-001"

  mitigates:          # 방어용
    - id: "ATK-INJECT-SQL-001"
```

**최소 관계 수**: 5개 이상

---

## 4. 권장 섹션

### 4.1 Core Concepts (핵심 개념)

```yaml
core_concepts:
  - name: "Thread Pool"
    description: "동시 요청 처리를 위한 스레드 재사용 메커니즘"
    security_relevance: "과도한 요청 시 DoS 가능"

  - name: "Session Management"
    description: "사용자 상태 유지 메커니즘"
    security_relevance: "세션 하이재킹 공격 대상"
```

**작성 기준**: 해당 원자 이해에 필수적인 개념만 포함 (3-7개)

### 4.2 Security Profile (보안 프로파일)

```yaml
security:
  attack_surface:
    exposed_ports:
      - port: 8080
        service: "HTTP"
        risk: "medium"
    exposed_interfaces:
      - "Management Console"
      - "REST API"

  common_vulnerabilities:
    - id: "VUL-DESER-001"
      name: "Insecure Deserialization"
      cwe: "CWE-502"

  attack_techniques:
    - id: "ATK-RCE-DESER-001"
      name: "Deserialization RCE"
      mitre: "T1190"

  defenses:
    - id: "DEF-WAF-001"
      name: "Web Application Firewall"
      effectiveness: "high"
```

### 4.3 Products (제품)

```yaml
products:
  open_source:
    - name: "Apache Tomcat"
      vendor: "Apache Foundation"
      use_case: "경량, 단독 실행"

  commercial:
    - name: "Oracle WebLogic"
      vendor: "Oracle"
      use_case: "엔터프라이즈"
```

### 4.4 Protocols (프로토콜)

```yaml
protocols:
  inbound:
    - name: "HTTP/HTTPS"
      port: "8080, 8443"
      security: "TLS 권장"

  outbound:
    - name: "JDBC"
      target: "Database"

  management:
    - name: "JMX"
      security: "인증 필수"
```

### 4.5 Diagnosis (진단 힌트)

```yaml
diagnosis:
  fingerprinting:
    - method: "HTTP 헤더 확인"
      target: "Server 헤더"

  common_misconfigurations:
    - name: "Manager App Exposed"
      check: "GET /manager/html"
      risk: "Critical"
```

---

## 5. 메타데이터 - 필수

```yaml
metadata:
  created_at: "2025-01-28"
  updated_at: "2025-01-28"
  version: "1.0"
  author: "작성자"
  confidence: 0.95           # 0.0-1.0 신뢰도
  sources:
    - "OWASP Testing Guide"
    - "공식 문서 URL"
  tags: ["web", "java", "middleware"]
```

---

## 6. 품질 체크리스트

### 필수 항목
- [ ] ID가 명명 규칙을 따르는가?
- [ ] GR 좌표(Layer/Zone/Tags)가 모두 지정되었는가?
- [ ] definition의 what/why/how가 모두 작성되었는가?
- [ ] 관계가 5개 이상인가?
- [ ] 출처가 2개 이상 명시되었는가?
- [ ] confidence 값이 설정되었는가?

### 권장 항목
- [ ] core_concepts가 3개 이상인가?
- [ ] 보안 관련 원자의 경우 security 섹션이 있는가?
- [ ] 인프라 원자의 경우 products 섹션이 있는가?
- [ ] protocols 정보가 있는가?
- [ ] diagnosis 힌트가 있는가?

### 품질 기준
- [ ] 전문 용어가 적절히 설명되었는가?
- [ ] 문장이 명확하고 간결한가?
- [ ] 보안 관련성이 충분히 설명되었는가?
- [ ] 관계가 양방향으로 일관성 있는가?

---

## 7. 원자 유형별 특화 가이드

### 7.1 인프라 원자 (INFRA-*)

**필수 추가 섹션**:
- `products`: 실제 제품 목록
- `protocols`: 사용 프로토콜
- `security.attack_surface`: 노출 포트/인터페이스

**관계 중점**:
- `connects_upstream/downstream`: 네트워크 토폴로지
- `runs_on`: 실행 환경
- `vulnerable_to`: 관련 취약점

### 7.2 공격 원자 (ATK-*)

**필수 추가 섹션**:
- `mitre_mapping`: ATT&CK 매핑
- `typical_flow`: 공격 단계
- `indicators`: 탐지 지표

**관계 중점**:
- `targets`: 공격 대상 인프라
- `exploits`: 악용 취약점
- `enables`: 후속 공격
- `countered_by`: 방어 기법

### 7.3 방어 원자 (DEF-*)

**필수 추가 섹션**:
- `d3fend_mapping`: D3FEND 매핑
- `implementation`: 구현 방법
- `effectiveness`: 효과성 평가

**관계 중점**:
- `mitigates`: 완화 대상 (공격/취약점)
- `protects`: 보호 대상 인프라
- `requires`: 필요 조건
- `complements`: 보완 기법

### 7.4 취약점 원자 (VUL-*)

**필수 추가 섹션**:
- `cwe_id`: CWE 매핑
- `severity`: 심각도
- `exploitation`: 악용 방법

**관계 중점**:
- `affects`: 영향받는 인프라
- `exploited_by`: 악용 공격 기법
- `mitigated_by`: 완화 방법
- `related_cves`: 실제 CVE 사례

---

## 8. 작성 프로세스

```
1. 주제 선정
   └── 우선순위 목록에서 선택

2. 자료 조사
   ├── 공식 문서
   ├── MITRE/CWE/OWASP
   ├── 기술 블로그
   └── 실무 경험

3. 템플릿 복사
   └── atoms/_template.yaml

4. 섹션별 작성
   ├── Identity → Classification → Definition
   └── Relations → Security → Products → Metadata

5. 품질 검증
   ├── 체크리스트 확인
   └── 관계 일관성 검토

6. 피어 리뷰
   └── PR 생성 및 리뷰

7. 머지 및 인덱싱
   └── 관계 연결 확인
```

---

## 9. 참고 자료

### 9.1 레퍼런스 원자
- `atoms/infrastructure/INFRA-APP-WAS-001.yaml` - 인프라 표준 예시

### 9.2 외부 참조
- MITRE ATT&CK: https://attack.mitre.org/
- MITRE D3FEND: https://d3fend.mitre.org/
- CWE: https://cwe.mitre.org/
- OWASP: https://owasp.org/

### 9.3 스키마 참조
- `schema/atom_schema.yaml` - 공식 스키마
- `schema/relation_types.yaml` - 관계 타입 정의

