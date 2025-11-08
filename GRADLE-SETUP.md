# 🔧 Gradle 설정 가이드

## Gradle Wrapper JAR 생성

Gradle Wrapper를 사용하면 Gradle을 별도로 설치하지 않아도 프로젝트를 빌드할 수 있습니다.

---

## 🚀 Wrapper 생성 방법

### 방법 1: 로컬 Gradle 사용 (권장)

시스템에 Gradle이 설치되어 있는 경우:

```bash
cd dashboard/backend

# Gradle Wrapper 생성
gradle wrapper --gradle-version 8.5

# 실행 권한 부여 (Linux/Mac)
chmod +x gradlew
```

### 방법 2: Docker 사용

Gradle이 설치되어 있지 않은 경우:

```bash
cd dashboard/backend

# Docker로 Wrapper 생성
docker run --rm -v "$PWD":/app -w /app gradle:8.5-jdk17 \
  gradle wrapper --gradle-version 8.5

# 실행 권한 부여 (Linux/Mac)
chmod +x gradlew
```

### 방법 3: 수동 다운로드

1. **gradle-wrapper.jar 다운로드**

```bash
cd dashboard/backend/gradle/wrapper

# Wrapper JAR 다운로드
curl -L -o gradle-wrapper.jar \
  https://github.com/gradle/gradle/raw/v8.5.0/gradle/wrapper/gradle-wrapper.jar
```

2. **권한 설정**

```bash
chmod +x ../../gradlew
```

---

## ✅ 확인

Wrapper가 올바르게 생성되었는지 확인:

```bash
cd dashboard/backend

# Gradle 버전 확인
./gradlew --version

# 빌드 테스트
./gradlew build
```

**예상 출력**:
```
Gradle 8.5
------------------------------------------------------------

Build time:   2023-11-29 14:08:57 UTC
Revision:     28aca86a7180baa17117e0e5ba01d8ea9feca598

Kotlin:       1.9.20
Groovy:       3.0.17
Ant:          Apache Ant(TM) version 1.10.13 compiled on January 4 2023
JVM:          17.0.9 (Eclipse Adoptium 17.0.9+9)
OS:           Linux 5.15.0 amd64
```

---

## 📁 생성되는 파일들

```
dashboard/backend/
├── gradlew                        # Unix용 실행 스크립트
├── gradlew.bat                    # Windows용 실행 스크립트
└── gradle/
    └── wrapper/
        ├── gradle-wrapper.jar     # Wrapper 실행 JAR
        └── gradle-wrapper.properties  # Wrapper 설정
```

---

## 🐛 트러블슈팅

### 문제: Permission denied

**원인**: gradlew 실행 권한 없음

**해결**:
```bash
chmod +x gradlew
```

### 문제: Could not find or load main class

**원인**: gradle-wrapper.jar 누락

**해결**: 위의 "수동 다운로드" 방법 참고

### 문제: Gradle version mismatch

**원인**: 버전 불일치

**해결**:
```bash
# Wrapper 재생성
./gradlew wrapper --gradle-version 8.5
```

---

## 🔄 Wrapper 업데이트

Gradle 버전 업그레이드:

```bash
# 8.6으로 업그레이드 예시
./gradlew wrapper --gradle-version 8.6

# 자동으로 다운로드 및 업데이트됨
```

---

## 📝 참고사항

- **Wrapper JAR는 Git에 포함**: 다른 개발자가 Gradle 설치 없이 바로 빌드 가능
- **자동 다운로드**: 첫 실행 시 Gradle이 자동으로 다운로드됨
- **버전 고정**: gradle-wrapper.properties에 명시된 버전 사용

---

## 🎯 Maven에서 Gradle로 마이그레이션 체크리스트

- [x] build.gradle 생성
- [x] settings.gradle 생성
- [x] Gradle Wrapper 생성
- [ ] gradle-wrapper.jar 생성 (위 방법 중 하나 사용)
- [x] Dockerfile 수정
- [x] 문서 업데이트
- [ ] 빌드 테스트
- [ ] CI/CD 파이프라인 업데이트

---

완료! 🎉
