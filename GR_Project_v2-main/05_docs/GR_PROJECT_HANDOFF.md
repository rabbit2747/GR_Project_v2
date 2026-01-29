# GR Ontology Project - Handoff Document

> **Version**: 1.0
> **Date**: 2025-01-29
> **Status**: Phase 1 Complete (103/100 atoms)

---

## 1. Project Overview

### 1.1 What is GR?

GR (Infrastructure Context-Based Unified Security Ontology)은 보안 지식을 인프라 컨텍스트 기반으로 구조화하는 온톨로지 시스템이다.

**Core Idea**: "Security happens on infrastructure" - 모든 공격/방어/취약점에 WHERE(인프라 컨텍스트)를 부여하여 AI가 추론할 수 있게 한다.

### 1.2 Architecture

```
3D Coordinate System = Layer x Zone x Tags

Layer (수직 - 인프라 계층):
  L1: Physical  →  L2: Network  →  L3: OS  →  L4: Middleware
  L5: Database  →  L6: Runtime  →  L7: Application  →  Cross: 공통

Zone (수평 - 신뢰 경계):
  Zone0A: External Untrusted (0%)
  Zone0B: External Partners (10%)
  Zone1:  DMZ (20%)
  Zone2:  Application (30%)
  Zone3:  Database (40%)
  Zone4:  Management (50%)
  Zone5:  Core/Secrets (60%)

Tags (기능): RECON, EXPLOIT, AUTH, WEB, API, CLOUD, ...
```

### 1.3 Atom = Knowledge Unit

모든 지식은 **Atom**(원자)이라는 자기 완결적 YAML 노드로 표현된다. 원자는 **Relations**(관계)로 연결되어 그래프를 형성한다.

```yaml
Atom 구조:
├── identity:      ID, 이름, 정규화명, 별칭
├── classification: domain, type, abstraction_level, gr_coordinates
├── definition:    what(정의), why(중요성), how(메커니즘)
├── relations:     structural, causal, conditional, applicability
├── properties:    기술적 상세 (도메인별 확장)
└── metadata:      trust, temporal, security, ai(embedding_text, keywords)
```

### 1.4 Key Design Principles

1. **AI-First**: 인간이 아닌 AI가 주 소비자. 명시적, 구조적, 파싱 가능한 형태
2. **Everything is Graph**: 노드(원자) + 엣지(관계)로 모든 지식 표현
3. **Single Source of Truth**: 하나의 개념 = 하나의 원자 (중복 금지)
4. **Referenced Terms Rule**: 원자에서 언급되는 모든 용어는 그 자체로 원자가 있어야 함

---

## 2. Phase 1 Completion Report

### 2.1 Summary

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Total Atoms | 100 | **103** | COMPLETE |
| Categories Covered | 5 | 8 | EXCEEDED |
| Domain | Web App Security | Web App Security | ON TARGET |

### 2.2 Atom Inventory by Category

#### Technology (12 atoms)

| ID | Name | Layer/Zone |
|----|------|------------|
| TECH-PROTOCOL-HTTP-001 | HTTP | L7/Zone0A |
| TECH-PROTOCOL-HTTPS-001 | HTTPS/TLS | L7/Zone0A |
| TECH-PROTOCOL-TCP-001 | TCP | L2/Cross |
| TECH-LANG-HTML-001 | HTML | L7/Zone2 |
| TECH-LANG-JAVASCRIPT-001 | JavaScript | L7/Zone0A |
| TECH-LANG-SQL-001 | SQL | L5/Zone3 |
| TECH-FORMAT-JSON-001 | JSON | L7/Cross |
| TECH-FORMAT-XML-001 | XML | L7/Cross |
| TECH-CONCEPT-COOKIE-001 | Cookie | L7/Zone2 |
| TECH-CONCEPT-DOM-001 | DOM | L7/Zone0A |
| TECH-CONCEPT-SESSION-001 | Session | L7/Zone2 |
| TECH-CONCEPT-SHELL-001 | Shell | L3/Zone4 |

#### Infrastructure (11 atoms)

| ID | Name | Layer/Zone |
|----|------|------------|
| INFRA-APP-WAS-001 | Web Application Server | L7/Zone2 |
| INFRA-APP-WEBSERVER-001 | Web Server | L7/Zone1 |
| INFRA-APP-API-001 | REST API Server | L7/Zone2 |
| INFRA-APP-WEBAPP-001 | Web Application | L7/Zone2 |
| INFRA-DATA-RDBMS-001 | Relational Database | L5/Zone3 |
| INFRA-DATA-CACHE-001 | Cache Server | L5/Zone3 |
| INFRA-NET-LB-001 | Load Balancer | L2/Zone1 |
| INFRA-NET-WAF-001 | Web Application Firewall | L7/Zone1 |
| INFRA-NET-FIREWALL-001 | Firewall | L2/Zone1 |
| INFRA-NET-CDN-001 | CDN | L7/Zone0B |
| INFRA-NET-DNS-001 | DNS Server | L7/Zone0B |

#### Attacks (16 new-scheme atoms + 18 legacy SQLi detail atoms = 34)

**New-Scheme Attacks (16)**:

| ID | Name | CWE | CVSS |
|----|------|-----|------|
| ATK-INJECT-SQL-001 | SQL Injection | CWE-89 | 9.8 |
| ATK-INJECT-XSS-001 | Cross-Site Scripting | CWE-79 | 6.1 |
| ATK-INJECT-CMD-001 | Command Injection | CWE-78 | 9.8 |
| ATK-INJECT-XML-001 | XML Injection (XXE) | CWE-611 | 9.1 |
| ATK-AUTH-BRUTEFORCE-001 | Brute Force | CWE-307 | 7.5 |
| ATK-AUTH-BYPASS-001 | Authentication Bypass | CWE-287 | 9.8 |
| ATK-AUTH-CREDSTUFF-001 | Credential Stuffing | CWE-307 | 8.1 |
| ATK-AUTH-CSRF-001 | CSRF | CWE-352 | 6.5 |
| ATK-SESSION-HIJACK-001 | Session Hijacking | CWE-384 | 8.0 |
| ATK-SERVER-SSRF-001 | SSRF | CWE-918 | 8.6 |
| ATK-SERVER-DESER-001 | Insecure Deserialization | CWE-502 | 9.8 |
| ATK-SERVER-FILEUPLOAD-001 | Malicious File Upload | CWE-434 | 9.8 |
| ATK-SERVER-PATH-001 | Path Traversal | CWE-22 | 7.5 |
| ATK-SERVER-RFI-001 | Remote File Inclusion | CWE-98 | 9.8 |
| ATK-WEB-CLICKJACK-001 | Clickjacking | CWE-1021 | 6.1 |
| ATK-NET-MITM-001 | Man-in-the-Middle | CWE-300 | 8.1 |

**Legacy SQLi Detail Atoms (18)** (GR-SEC-* ID scheme):
- `GR-SEC-TEC-00001 ~ 00010`: SQLi Techniques (10)
- `GR-SEC-INS-P0001 ~ P0005`: SQLi Payloads (5)
- `GR-SEC-INS-F0001 ~ F0003`: SQLi Fingerprints (3)

#### Vulnerabilities (15 atoms)

| ID | Name | CWE | CVSS |
|----|------|-----|------|
| VUL-INJECT-SQL-001 | SQL Injection Vulnerability | CWE-89 | 9.8 |
| VUL-INJECT-XSS-001 | XSS Vulnerability | CWE-79 | 6.1 |
| VUL-INJECT-CMD-001 | Command Injection Vulnerability | CWE-78 | 9.8 |
| VUL-AUTH-BROKEN-001 | Broken Authentication | CWE-287 | 8.2 |
| VUL-AUTH-SESSION-001 | Session Management Flaw | CWE-384 | 7.5 |
| VUL-CRYPTO-WEAK-001 | Weak Cryptography | CWE-327 | 7.5 |
| VUL-CONFIG-MISCONFIG-001 | Security Misconfiguration | CWE-16 | 6.5 |
| VUL-ACCESS-BROKEN-001 | Broken Access Control | CWE-284 | 8.6 |
| VUL-DATA-EXPOSURE-001 | Sensitive Data Exposure | CWE-200 | 7.5 |
| VUL-DESER-INSECURE-001 | Insecure Deserialization | CWE-502 | 9.8 |
| VUL-COMPONENT-VULN-001 | Vulnerable Components | CWE-1035 | 7.5 |
| VUL-LOG-INSUFFICIENT-001 | Insufficient Logging | CWE-778 | 5.3 |
| VUL-SSRF-001 | SSRF Vulnerability | CWE-918 | 8.6 |
| VUL-XXE-001 | XXE Vulnerability | CWE-611 | 9.1 |
| VUL-PATH-TRAVERSAL-001 | Path Traversal | CWE-22 | 7.5 |

#### Defense - Prevention (12 atoms)

| ID | Name |
|----|------|
| DEF-PREVENT-PARAMQUERY-001 | Parameterized Query |
| DEF-PREVENT-INPUTVAL-001 | Input Validation |
| DEF-PREVENT-OUTPUTENC-001 | Output Encoding |
| DEF-PREVENT-CSP-001 | Content Security Policy |
| DEF-PREVENT-CSRF-TOKEN-001 | CSRF Token |
| DEF-PREVENT-HTTPS-001 | HTTPS/TLS Enforcement |
| DEF-PREVENT-CORS-001 | CORS Configuration |
| DEF-PREVENT-HEADERS-001 | Security Headers |
| DEF-PREVENT-RATELIMIT-001 | Rate Limiting |
| DEF-PREVENT-MFA-001 | Multi-Factor Authentication |
| DEF-PREVENT-ENCRYPT-001 | Data Encryption |
| DEF-PREVENT-SANDBOX-001 | Sandboxing |

#### Defense - Detection (5 atoms)

| ID | Name |
|----|------|
| DEF-DETECT-WAF-001 | WAF Detection Rules |
| DEF-DETECT-IDS-001 | Intrusion Detection System |
| DEF-DETECT-LOGGING-001 | Security Logging |
| DEF-DETECT-MONITORING-001 | Security Monitoring/SIEM |
| DEF-DETECT-ANOMALY-001 | Anomaly Detection |

#### Defense - Response (3 atoms)

| ID | Name |
|----|------|
| DEF-RESPOND-INCIDENT-001 | Incident Response |
| DEF-RESPOND-BLOCK-001 | IP/Request Blocking |
| DEF-RESPOND-QUARANTINE-001 | Account Quarantine |

#### Tools (8 atoms)

| ID | Name | Type |
|----|------|------|
| TOOL-OFFENSE-BURP-001 | Burp Suite | Offensive |
| TOOL-OFFENSE-SQLMAP-001 | SQLMap | Offensive |
| TOOL-OFFENSE-ZAP-001 | OWASP ZAP | Offensive |
| TOOL-OFFENSE-METASPLOIT-001 | Metasploit Framework | Offensive |
| TOOL-DEFENSE-MODSEC-001 | ModSecurity WAF | Defensive |
| TOOL-AUDIT-NMAP-001 | Nmap | Audit |
| TOOL-AUDIT-NIKTO-001 | Nikto | Audit |
| TOOL-AUDIT-WIRESHARK-001 | Wireshark | Audit |

#### Legacy Concepts (3 atoms)

| ID | Name |
|----|------|
| GR-SEC-CON-00001 | Injection (개념) |
| GR-SEC-CON-00002 | SQL Injection (개념) |
| GR-SEC-PRI-00001 | Untrusted Input-Code Mixing Danger (원칙) |

---

## 3. Known Issues

### 3.1 Dangling References (59개)

원자들의 `relations` 섹션에서 참조하지만 아직 YAML 파일이 없는 ID가 **59개** 있다.

#### A. 추상 부모 개념 (20개) - 최우선 해결

이들은 여러 원자가 `is_a`로 참조하는 상위 카테고리 개념이다.

| Missing ID | 참조하는 원자 수 | 설명 |
|-----------|----------------|------|
| TECH-CONCEPT-VULNERABILITY-001 | 15 | 모든 VUL-* 원자의 부모 |
| TECH-CONCEPT-DEFENSE-001 | 12 | 모든 DEF-PREVENT-* 의 부모 |
| TECH-CONCEPT-AUTH-ATTACK-001 | 5 | ATK-AUTH-*/ATK-SESSION-* 부모 |
| TECH-CONCEPT-SERVER-ATTACK-001 | 5 | ATK-SERVER-* 부모 |
| TECH-CONCEPT-NETWORK-DEVICE-001 | 4 | INFRA-NET-* 부모 |
| TECH-CONCEPT-PROTOCOL-001 | 2 | TECH-PROTOCOL-* 부모 |
| TECH-CONCEPT-DATA-FORMAT-001 | 2 | TECH-FORMAT-* 부모 |
| TECH-CONCEPT-DATABASE-001 | 2 | INFRA-DATA-* 부모 |
| TECH-CONCEPT-APPLICATION-001 | 1 | INFRA-APP-WEBAPP 부모 |
| TECH-CONCEPT-BROWSER-001 | 1 | DOM의 part_of 대상 |
| TECH-CONCEPT-CERTIFICATE-001 | 1 | HTTPS requires 대상 |
| TECH-CONCEPT-CLIENT-ATTACK-001 | 1 | Clickjacking 부모 |
| TECH-CONCEPT-FIREWALL-001 | 1 | WAF 부모 |
| TECH-CONCEPT-MARKUP-001 | 1 | HTML 부모 |
| TECH-CONCEPT-NETWORK-ATTACK-001 | 1 | MITM 부모 |
| TECH-CONCEPT-OS-001 | 1 | Shell의 part_of 대상 |
| TECH-CONCEPT-PROGRAMMING-LANG-001 | 1 | JavaScript 부모 |
| TECH-CONCEPT-QUERY-LANG-001 | 1 | SQL 부모 |
| TECH-CONCEPT-SERVER-001 | 1 | WebServer 부모 |
| TECH-CONCEPT-STATE-MGMT-001 | 1 | Session 부모 |

#### B. 누락 공격 기법 (12개)

| Missing ID | 참조 출처 | 관계 |
|-----------|----------|------|
| ATK-SESSION-FIXATION-001 | TECH-CONCEPT-SESSION-001 | enables |
| ATK-SERVER-IDOR-001 | ATK-AUTH-BYPASS-001 | enables |
| ATK-POST-BACKDOOR-001 | ATK-INJECT-CMD-001 | causes |
| ATK-POST-LATERAL-001 | ATK-INJECT-CMD-001 | enables |
| ATK-PRIV-ESCAPE-001 | DEF-PREVENT-SANDBOX-001 | prevents |
| ATK-EXEC-RCE-001 | DEF-PREVENT-SANDBOX-001 | prevents |
| ATK-NET-SNIFF-001 | DEF-PREVENT-ENCRYPT/HTTPS-001 | prevents |
| ATK-DATA-LEAK-001 | DEF-PREVENT-ENCRYPT-001 | prevents |
| ATK-WEB-CORS-MISCONFIG-001 | DEF-PREVENT-CORS-001 | prevents |
| ATK-WEB-MIME-SNIFF-001 | DEF-PREVENT-HEADERS-001 | prevents |
| ATK-NETWORK-MITM-001 | TECH-PROTOCOL-HTTPS-001 | (naming bug) |
| ATK-NETWORK-SNIFF-001 | TECH-PROTOCOL-HTTPS-001 | prevents |

#### C. 누락 인프라 (21개)

| Missing ID | 참조 출처 | 비고 |
|-----------|----------|------|
| INFRA-APP-WEB-001 | 9 DEF-PREVENT-* | **Naming bug**: INFRA-APP-WEBAPP-001이어야 함 |
| INFRA-APP-SPA-001 | TECH-LANG-JAVASCRIPT/API | SPA 원자 미생성 |
| INFRA-APP-MOBILE-API-001 | INFRA-APP-API-001 | Mobile API 원자 미생성 |
| INFRA-APP-WAS-TOMCAT-001 | INFRA-APP-WAS-001 | WAS 하위 인스턴스 |
| INFRA-APP-WAS-JBOSS-001 | INFRA-APP-WAS-001 | WAS 하위 인스턴스 |
| INFRA-APP-WAS-WEBLOGIC-001 | INFRA-APP-WAS-001 | WAS 하위 인스턴스 |
| INFRA-APP-WAS-WEBSPHERE-001 | INFRA-APP-WAS-001 | WAS 하위 인스턴스 |
| INFRA-NET-NETWORK-001 | DEF-DETECT-*, RESPOND-*, TOOL | 범용 네트워크 원자 |
| INFRA-NET-001 | DEF-PREVENT-ENCRYPT/HTTPS | 범용 네트워크 원자 |
| INFRA-NET-SERVER-001 | VUL-CONFIG-MISCONFIG-001 | 범용 서버 원자 |
| INFRA-SYS-SERVER-001 | DEF-DETECT-*, RESPOND-*, TOOL | 시스템 서버 원자 |
| INFRA-COMPUTE-VM-001 | INFRA-APP-WAS-001 | VM 원자 |
| INFRA-COMPUTE-CONTAINER-001 | DEF-PREVENT-SANDBOX-001 | 컨테이너 원자 |
| INFRA-COMPUTE-SERVER-001 | DEF-PREVENT-SANDBOX-001 | 서버 원자 |
| INFRA-RUNTIME-JVM-001 | INFRA-APP-WAS-001 | JVM 런타임 |
| INFRA-RUNTIME-CONTAINER-001 | INFRA-APP-WAS-001 | 컨테이너 런타임 |
| INFRA-RUNTIME-K8S-001 | INFRA-APP-WAS-001 | Kubernetes |
| INFRA-DATA-MQ-001 | INFRA-APP-WAS-001 | Message Queue |
| INFRA-DATA-STORAGE-001 | DEF-PREVENT-ENCRYPT-001 | 스토리지 |
| INFRA-IAM-LDAP-001 | INFRA-APP-WAS-001 | LDAP/AD |
| INFRA-CLOUD-001 | VUL-CONFIG-MISCONFIG-001 | 클라우드 |

#### D. 기타 누락 (6개)

| Missing ID | 참조 출처 | 비고 |
|-----------|----------|------|
| TECH-PROTOCOL-TLS-001 | TECH-PROTOCOL-HTTPS-001 | TLS 프로토콜 |
| GR-SEC-CON-00001 | ATK-INJECT-* 4개 | 이미 존재하나 relations에서 불일치 가능 |
| CON-MIDDLEWARE-001 | INFRA-APP-WAS-001 | 미들웨어 개념 |
| VUL-LOGGING-INSUFFICIENT-001 | DEF-DETECT-LOGGING-001 | **Naming bug**: VUL-LOG-INSUFFICIENT-001 |
| VUL-MONITORING-INSUFFICIENT-001 | DEF-DETECT-MONITORING-001 | 모니터링 취약점 미생성 |
| VUL-RESPONSE-INSUFFICIENT-001 | DEF-RESPOND-INCIDENT-001 | 대응 부재 취약점 미생성 |

### 3.2 Naming Inconsistencies (즉시 수정 필요)

| File | 잘못된 참조 | 올바른 ID |
|------|-----------|----------|
| TECH-PROTOCOL-HTTPS-001 | `ATK-NETWORK-MITM-001` | `ATK-NET-MITM-001` |
| 9 DEF-PREVENT-* | `INFRA-APP-WEB-001` | `INFRA-APP-WEBAPP-001` |
| DEF-DETECT-LOGGING-001 | `VUL-LOGGING-INSUFFICIENT-001` | `VUL-LOG-INSUFFICIENT-001` |

### 3.3 ID Scheme Inconsistency

두 가지 ID 체계가 혼재:

1. **Legacy** (초기 SQLi 작업): `GR-SEC-{TYPE}-{SEQUENCE}` (예: GR-SEC-TEC-00001)
2. **Current** (Phase 1 표준): `{CATEGORY}-{SUBCATEGORY}-{NAME}-{SEQUENCE}` (예: ATK-INJECT-SQL-001)

`id_registry.yaml`은 Legacy 체계만 관리하고 있어, Current 체계 원자들은 미등록 상태.

---

## 4. Directory Structure

```
GR_Project_v2/
├── 01_ontology/                              # 온톨로지 정의
│   ├── constitution/
│   │   └── GR_KNOWLEDGE_ATOMIZATION_CONSTITUTION.md  # 헌법 v2.0
│   ├── guides/
│   │   ├── ATOM_WRITING_GUIDE_v1.0.md        # 원자 작성 가이드
│   │   ├── PHASE1_ATOM_LIST.md               # Phase 1 계획 (업데이트 필요)
│   │   └── QUICK_START.md                     # 빠른 시작 가이드
│   ├── schema/
│   │   ├── core/
│   │   │   ├── atom_schema.yaml              # 원자 스키마 v1.2
│   │   │   └── relation_types.yaml           # 관계 유형 v1.2
│   │   └── extensions/                        # (비어있음)
│   └── taxonomy/
│       ├── layers.yaml                        # L1-L7 + Cross 정의
│       ├── zones.yaml                         # Zone0A-5 정의
│       └── function_tags.yaml                 # 기능 태그 정의
│
├── 02_knowledge_base/                         # 지식 원자 저장소
│   ├── id_registry.yaml                       # ID 레지스트리 (legacy만)
│   ├── concepts/                              # 기초 개념 (3 atoms)
│   │   ├── GR-SEC-CON-00001.yaml             # Injection
│   │   ├── GR-SEC-CON-00002.yaml             # SQL Injection
│   │   └── principles/
│   │       └── GR-SEC-PRI-00001.yaml         # Untrusted Input Danger
│   ├── technology/                            # 기술 원자 (12 atoms)
│   │   ├── protocols/                         # HTTP, HTTPS, TCP
│   │   ├── languages/                         # HTML, JS, SQL
│   │   ├── formats/                           # JSON, XML
│   │   └── concepts/                          # Cookie, DOM, Session, Shell
│   ├── infrastructure/                        # 인프라 원자 (11 atoms)
│   │   └── (INFRA-APP-*, INFRA-DATA-*, INFRA-NET-*)
│   ├── security/
│   │   ├── attacks/                           # 공격 원자 (34 atoms)
│   │   │   ├── injection/                     # SQL/XSS/CMD/XML + sqli/ (legacy)
│   │   │   ├── authentication/                # CSRF, BruteForce, Bypass, CredStuff, Hijack
│   │   │   ├── server-side/                   # SSRF, Deser, FileUpload, Path, RFI
│   │   │   ├── client-side/                   # Clickjacking
│   │   │   └── network/                       # MITM
│   │   ├── vulnerabilities/                   # 취약점 원자 (15 atoms)
│   │   ├── defenses/
│   │   │   ├── prevention/                    # 12 atoms
│   │   │   ├── detection/                     # 5 atoms
│   │   │   └── response/                      # 3 atoms
│   │   └── tools/                             # 보안 도구 (8 atoms)
│   └── mappings/                              # 외부 표준 매핑 (비어있음)
│       ├── cwe/
│       ├── mitre_attack/
│       ├── mitre_defend/
│       └── owasp/
│
├── 03_applications/                           # 애플리케이션 (미구현)
│   ├── atlas/                                 # 지식 시각화
│   ├── dast/                                  # 동적 보안 테스트
│   ├── edu/                                   # 교육
│   └── iac/                                   # IaC 생성
│
├── 04_infrastructure/                         # 인프라 (미구현)
│   ├── api/                                   # FastAPI
│   ├── database/                              # PostgreSQL, Neo4j, Vector DB
│   └── tools/                                 # atom_generator, migrator, validator
│
├── 05_docs/                                   # 문서
│   ├── vision/
│   │   ├── GR_ONTOLOGY_MASTERPLAN_v1.0.md    # 마스터플랜
│   │   └── (기타 비전 문서)
│   ├── guides/
│   └── technical/
│
└── 99_references/                             # 참조 자료
    ├── papers/
    └── strix/                                 # Strix 프로젝트 참조
```

---

## 5. Key Conventions Reference

### 5.1 Atom YAML Template

```yaml
# GR Atom: [Name]
# Version: 1.0
# Created: YYYY-MM-DD

identity:
  id: "[CATEGORY]-[SUBCATEGORY]-[NAME]-001"
  name: "[Human-Readable Name]"
  normalization:
    normalized_name: "[lowercase space-separated keywords]"
    normalization_version: "1.0"
  aliases:
    - "[Korean name]"
    - "[Alternative English name]"

classification:
  domain: security
  type: [technique|vulnerability|control|tool|component]
  abstraction_level: [1=Instance|2=Type|3=Concept|4=Principle]
  gr_coordinates:
    layer: "[L1-L7|Cross]"
    zone: "[Zone0A-Zone5|Cross]"
    tags: ["TAG1", "TAG2"]

definition:
  what: |
    [Korean description - 50~500 chars]
  why: |
    [Korean importance]
  how: |
    [Korean mechanism]

relations:
  structural:
    is_a: ["PARENT-ID"]
  causal:
    enables/prevents/exploited_by: ["TARGET-ID"]
  applicability:
    applies_to: ["INFRA-ID"]

properties:
  technical:
    [domain-specific fields]
  security:
    impact:
      confidentiality: "[CRITICAL|HIGH|MEDIUM|LOW]"
      integrity: "[CRITICAL|HIGH|MEDIUM|LOW]"
      availability: "[CRITICAL|HIGH|MEDIUM|LOW]"
    cvss_base: [0.0-10.0]
    cwe_id: "CWE-XXX"

metadata:
  trust:
    source: official
    references:
      - "[Reference 1]"
    confidence: 1.0
    verified:
      status: verified
      date: YYYY-MM-DD
      by: "GR System"
  temporal:
    created: YYYY-MM-DD
    modified: YYYY-MM-DD
    revision: 1
  security:
    sensitivity: public
    weaponization_risk: [low|medium|high]
  ai:
    embedding_text: |
      [50-200 words summarizing the atom for LLM embedding]
    search_keywords:
      - "[keyword1]"
      - "[keyword2]"
    related_queries:
      - "[query1]"
      - "[query2]"
```

### 5.2 ID Naming Convention

```
Category Prefixes:
  TECH-PROTOCOL-*     기술 - 프로토콜
  TECH-LANG-*         기술 - 언어
  TECH-FORMAT-*       기술 - 데이터 형식
  TECH-CONCEPT-*      기술 - 개념
  INFRA-APP-*         인프라 - 애플리케이션
  INFRA-DATA-*        인프라 - 데이터
  INFRA-NET-*         인프라 - 네트워크
  INFRA-RUNTIME-*     인프라 - 런타임
  INFRA-COMPUTE-*     인프라 - 컴퓨팅
  INFRA-IAM-*         인프라 - 인증/인가
  ATK-INJECT-*        공격 - 인젝션
  ATK-AUTH-*          공격 - 인증
  ATK-SESSION-*       공격 - 세션
  ATK-SERVER-*        공격 - 서버측
  ATK-WEB-*           공격 - 웹/클라이언트
  ATK-NET-*           공격 - 네트워크
  VUL-*               취약점
  DEF-PREVENT-*       방어 - 예방
  DEF-DETECT-*        방어 - 탐지
  DEF-RESPOND-*       방어 - 대응
  TOOL-OFFENSE-*      도구 - 공격용
  TOOL-DEFENSE-*      도구 - 방어용
  TOOL-AUDIT-*        도구 - 감사용
```

### 5.3 Relation Types (Canonical Only)

```
Structural:  is_a, part_of, instance_of, abstracts
Causal:      causes, enables, prevents
Conditional: requires, conflicts_with, alternative_to
Temporal:    precedes, supersedes
Applicability: applies_to, effective_against
Epistemic:   contradicts, disputes, refines
```

**Rule**: 역방향(inverse) 관계는 저장하지 않고 쿼리 시 유도한다.

---

## 6. Next Steps (TODO)

### 6.1 Immediate Fixes (P0)

- [ ] **Naming bug 수정 (3건)**: Section 3.2의 잘못된 참조 ID 수정
- [ ] **id_registry.yaml 업데이트**: Current 체계 원자 82개 등록
- [ ] **PHASE1_ATOM_LIST.md 업데이트**: 진행률 반영 (모든 항목 완료 표시)

### 6.2 Dangling References Resolution (P1)

우선순위 순서:

1. **추상 부모 개념 20개 생성** (TECH-CONCEPT-*-001) - 모든 원자의 is_a 루트
2. **INFRA-APP-WEB-001 참조 수정** - INFRA-APP-WEBAPP-001로 일괄 변경
3. **PHASE1_ATOM_LIST.md에 있는 미생성 P0/P1 원자 생성**:
   - ATK-SESSION-FIXATION-001
   - ATK-SERVER-IDOR-001
   - INFRA-APP-SPA-001
   - INFRA-DATA-MQ-001
   - INFRA-RUNTIME-* (JVM, Container, K8s)
   - TECH-PROTOCOL-TLS-001
4. **나머지 dangling reference 원자 생성** (post-exploitation, sniffing 등)

### 6.3 Phase 2 Expansion (P2)

마스터플랜 기준 Phase 2 목표:

| Area | Target |
|------|--------|
| Total Atoms | 500 |
| Total Relations | 2000+ |
| Network Security | 120 atoms |
| Cloud Security | Domain expansion |
| MITRE ATT&CK | Top 50 complete mapping |
| D3FEND | Defense mapping |
| CWE/CVE | Integration |

Phase 2 우선 확장 도메인:
- Network Security (네트워크 보안)
- Cloud Security (AWS/Azure/GCP)
- Container Security (Docker/K8s)
- Authentication & Authorization (OAuth, JWT, SAML)
- API Security (REST, GraphQL)

### 6.4 Infrastructure Development (P3)

마스터플랜의 기술 스택:

- [ ] PostgreSQL 15+ (Phase 1 primary DB)
- [ ] Neo4j (Phase 2 graph DB)
- [ ] pgvector/Pinecone (Vector DB for RAG)
- [ ] FastAPI + Pydantic (API)
- [ ] Claude/GPT API + LiteLLM (AI)
- [ ] Docker + Kubernetes (Deployment)
- [ ] Atom Validator tool
- [ ] Atom Generator tool

### 6.5 Quality Criteria Checklist

원자 품질 기준 (새 원자 생성 시 확인):

- [ ] definition.what, why, how 모두 존재
- [ ] 최소 5개 relations
- [ ] gr_coordinates (layer, zone, tags) 지정
- [ ] 보안 정보: CWE, CVSS (해당 시)
- [ ] metadata.ai.embedding_text: 50-200 단어
- [ ] metadata.ai.search_keywords: 5개 이상
- [ ] 참조 소스 2개 이상
- [ ] 모든 참조 ID가 실제 존재하는지 확인

---

## 7. Session Continuation Guide

### 새 세션에서 작업 재개 시

1. **이 문서 읽기**: `05_docs/GR_PROJECT_HANDOFF.md`
2. **온톨로지 헌법 참조**: `01_ontology/constitution/GR_KNOWLEDGE_ATOMIZATION_CONSTITUTION.md`
3. **스키마 참조**: `01_ontology/schema/core/atom_schema.yaml`, `relation_types.yaml`
4. **PHASE1_ATOM_LIST.md 확인**: 진행 상태
5. **Dangling references 확인**: 이 문서 Section 3.1

### 원자 생성 시 핵심 규칙

1. **Referenced Terms Rule**: 원자에서 참조되는 모든 용어는 자체 원자가 있어야 한다
2. **Korean Description**: definition은 한국어로 작성
3. **AI-First**: embedding_text는 LLM이 이해하기 좋은 형태로 작성
4. **No Duplicates**: normalized_name 유사도 >= 0.92이면 기존 원자 재사용
5. **Canonical Relations Only**: 역방향 관계 저장 금지
6. **Layer/Zone Assignment**: 모든 원자에 3D 좌표 부여

---

*Last updated: 2025-01-29 by Claude Code*
