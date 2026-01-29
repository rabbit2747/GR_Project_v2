# GR Ontology 빠른 시작 가이드

> 원자(Atom) 작성을 바로 시작하기 위한 최소 지식

---

## 1. 원자란?

**원자(Atom)**는 GR 온톨로지의 최소 지식 단위입니다.

```
하나의 원자 = 하나의 독립적인 지식
```

예시:
- "SQL Injection" → 하나의 원자
- "UNION-based SQLi" → 또 하나의 원자 (SQL Injection의 하위 기법)
- "Prepared Statement" → 또 하나의 원자 (방어 기법)

---

## 2. 원자의 기본 구조

```yaml
identity:
  id: "GR-SEC-ATK-00001"        # 고유 ID
  name: "SQL Injection"          # 이름

classification:
  domain: security               # 도메인
  type: technique                # 유형
  abstraction_level: 3           # 추상화 수준 (1-4)

definition:
  what: "사용자 입력이 SQL 쿼리에 삽입되어..."  # 정의
  why: "데이터 유출, 인증 우회 등이 가능..."    # 중요성
  how: "입력값에 SQL 구문을 삽입하여..."        # 동작 방식

relations:
  structural:
    is_a: ["GR-SEC-CON-00001"]   # Injection의 하위 개념
  causal:
    enables: ["GR-SEC-ATK-00010"]  # 데이터 유출 가능
  conditional:
    requires: ["GR-TECH-SQL-00001"]  # SQL 지식 필요
```

---

## 3. 추상화 수준 (1-4)

| Level | 이름 | 설명 | 예시 |
|-------|------|------|------|
| 4 | 원리 | 보편적 진리 | "입력과 코드 혼합 위험" |
| 3 | 개념 | 추상적 분류 | "Injection", "인증 우회" |
| 2 | 기법 | 구체적 방법 | "UNION-based SQLi" |
| 1 | 인스턴스 | 특정 사례 | "' OR 1=1 --" |

**규칙**: 하위 레벨은 반드시 상위 레벨을 참조

---

## 4. 주요 관계 타입

```
A is_a B        → A는 B의 하위 개념이다
A requires B    → A는 B를 필요로 한다
A enables B     → A는 B를 가능하게 한다
A prevents B    → A는 B를 방지한다
A applies_to B  → A는 B에 적용된다
```

---

## 5. 원자 작성 체크리스트

- [ ] ID는 규칙에 맞게 생성했는가?
- [ ] 추상화 수준이 적절한가?
- [ ] `what` 정의가 명확하고 간결한가?
- [ ] 최소 1개 이상의 관계가 있는가?
- [ ] 고립된 원자가 아닌가? (관계 없는 원자는 의미 없음)

---

## 6. 다음 단계

1. 상세 가이드: `ATOM_WRITING_GUIDE_v1.0.md`
2. 스키마: `../schema/core/atom_schema.yaml`
3. 관계 타입: `../schema/core/relation_types.yaml`
4. 헌법: `../constitution/GR_KNOWLEDGE_ATOMIZATION_CONSTITUTION.md`

---

*GR Ontology - 지식을 연결하여 AI가 맥락을 이해하게 한다*
