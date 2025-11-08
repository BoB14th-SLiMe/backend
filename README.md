# 🍃 Backend - Spring Boot API Server

## 개요

Spring Boot 3.2.1 기반의 OT 보안 모니터링 시스템 백엔드 API 서버입니다.

---

## 🔧 기술 스택

- **Spring Boot 3.2.1**
- **Java 17**
- **Gradle 8.5**
- **Elasticsearch Java Client 8.11.0**
- **Lombok**
- **Swagger/OpenAPI 3**

---

## 📦 주요 의존성

```gradle
// Spring Boot
spring-boot-starter-web
spring-boot-starter-webflux       // SSE 지원
spring-boot-starter-actuator      // 헬스체크

// Elasticsearch
elasticsearch-java:8.11.0
elasticsearch-rest-client:8.11.0

// Swagger
springdoc-openapi-starter-webmvc-ui:2.3.0

// Lombok
lombok
```

---

## 🚀 빌드 및 실행

### 1. Gradle 빌드

```bash
# 빌드
./gradlew clean build

# 테스트 제외 빌드
./gradlew clean bootJar

# 개발 모드 실행
./gradlew bootRun

# 테스트
./gradlew test
```

### 2. JAR 실행

```bash
# 빌드 후
java -jar build/libs/ot-security-backend.jar

# 프로파일 지정
java -jar build/libs/ot-security-backend.jar --spring.profiles.active=prod

# JVM 옵션
java -Xms512m -Xmx1024m -jar build/libs/ot-security-backend.jar
```

### 3. Docker 빌드

```bash
docker build -t ot-security-backend .
docker run -p 8080:8080 ot-security-backend
```

---

## ⚙️ 설정

### application.yml

```yaml
spring:
  application:
    name: ot-security-backend
  elasticsearch:
    uris: http://localhost:9200
    username: elastic
    password: ${ELASTICSEARCH_PASSWORD:}

server:
  port: 8080

ot-security:
  sse:
    timeout: 300000    # 5분
    heartbeat: 30000   # 30초
  refresh-interval: 5000  # 5초
  elasticsearch:
    packet-index: "ot-security-packets"
    threat-index: "ot-security-threats"
```

### 환경 변수

```bash
# Elasticsearch 비밀번호
export ELASTICSEARCH_PASSWORD=your_password

# 프로파일
export SPRING_PROFILES_ACTIVE=prod
```

---

## 🌐 API 엔드포인트

### REST API

#### Dashboard
```
GET /api/dashboard/stats
```
대시보드 전체 통계

#### Packets
```
GET /api/packets?page=0&size=20
```
패킷 목록 조회

#### Threats
```
GET /api/threats?page=0&size=20
```
위협 이벤트 목록 조회

### SSE (Server-Sent Events)

#### 전체 이벤트 구독
```
GET /api/sse/subscribe
```

#### 위협 전용
```
GET /api/sse/threats
```

#### 통계 전용
```
GET /api/sse/stats
```

### Actuator

```
GET /actuator/health      # 헬스체크
GET /actuator/info        # 애플리케이션 정보
GET /actuator/metrics     # 메트릭
```

### Swagger UI

```
http://localhost:8080/swagger-ui.html
```

---

## 📁 프로젝트 구조

```
src/main/java/com/ot/security/
├── OtSecurityApplication.java          # 메인 클래스
├── config/
│   ├── ElasticsearchConfig.java       # ES 클라이언트 설정
│   └── CorsConfig.java                # CORS 설정
├── controller/
│   ├── DashboardController.java       # 대시보드 API
│   ├── PacketController.java          # 패킷 API
│   ├── ThreatController.java          # 위협 API
│   └── SSEController.java             # SSE API
├── service/
│   ├── ElasticsearchService.java      # ES 쿼리 서비스
│   └── SSEService.java                # SSE 관리 서비스
├── model/
│   ├── Packet.java                    # 패킷 모델
│   └── ThreatEvent.java               # 위협 모델
├── dto/
│   └── DashboardStatsDTO.java         # 통계 DTO
└── scheduler/
    └── DataRefreshScheduler.java      # 실시간 업데이트 스케줄러
```

---

## 🔄 데이터 흐름

```
1. Elasticsearch ← Parser PC (데이터 저장)
2. ElasticsearchService → Elasticsearch (데이터 조회)
3. DataRefreshScheduler → 주기적 조회 (5초마다)
4. SSEService → 클라이언트 (실시간 푸시)
```

---

## 🧪 테스트

### 단위 테스트

```bash
./gradlew test
```

### API 테스트 (curl)

```bash
# 헬스체크
curl http://localhost:8080/actuator/health

# 대시보드 통계
curl http://localhost:8080/api/dashboard/stats

# 패킷 목록
curl http://localhost:8080/api/packets?page=0&size=10

# SSE 연결
curl -N http://localhost:8080/api/sse/subscribe
```

---

## 🐛 트러블슈팅

### 1. Elasticsearch 연결 실패

**문제**: Connection refused

**해결**:
```bash
# Elasticsearch 실행 확인
curl http://localhost:9200

# application.yml 확인
spring.elasticsearch.uris: http://localhost:9200
```

### 2. 빌드 실패

**문제**: Gradle 의존성 오류

**해결**:
```bash
# Gradle 캐시 삭제
./gradlew clean build --refresh-dependencies

# Gradle Wrapper 재다운로드
./gradlew wrapper --gradle-version 8.5
```

### 3. SSE 연결 끊김

**문제**: Timeout

**해결**: application.yml 수정
```yaml
ot-security:
  sse:
    timeout: 600000  # 10분으로 증가
```

---

## 📊 모니터링

### 로그 확인

```bash
# application.log
tail -f logs/application.log

# Docker
docker logs -f ot-security-backend
```

### Actuator 메트릭

```bash
# JVM 메모리
curl http://localhost:8080/actuator/metrics/jvm.memory.used

# HTTP 요청 통계
curl http://localhost:8080/actuator/metrics/http.server.requests
```

---

## 🚀 배포

### Docker 배포

```bash
# 이미지 빌드
docker build -t ot-security-backend:latest .

# 컨테이너 실행
docker run -d \
  --name ot-security-backend \
  -p 8080:8080 \
  -e SPRING_PROFILES_ACTIVE=prod \
  -e SPRING_ELASTICSEARCH_URIS=http://elasticsearch:9200 \
  ot-security-backend:latest
```

### JAR 배포

```bash
# 빌드
./gradlew clean bootJar

# 서버에 복사
scp build/libs/ot-security-backend.jar user@server:/app/

# 실행
ssh user@server
cd /app
nohup java -jar ot-security-backend.jar > app.log 2>&1 &
```

---

## 🔧 개발 가이드

### 새로운 API 추가

1. **Controller 생성**
```java
@RestController
@RequestMapping("/api/new")
public class NewController {
    @GetMapping
    public ResponseEntity<String> getNew() {
        return ResponseEntity.ok("New API");
    }
}
```

2. **Service 작성**
```java
@Service
public class NewService {
    // 비즈니스 로직
}
```

3. **Swagger 문서화**
```java
@Tag(name = "New", description = "New API")
@Operation(summary = "요약", description = "설명")
```

### Elasticsearch 쿼리 추가

```java
public List<Data> customQuery() throws IOException {
    SearchResponse<Data> response = elasticsearchClient.search(s -> s
        .index("index-name")
        .query(q -> q
            .match(m -> m
                .field("field")
                .query("value")
            )
        ),
        Data.class
    );
    return extractResults(response);
}
```

---

## 📚 참고 문서

- [Spring Boot Documentation](https://spring.io/projects/spring-boot)
- [Elasticsearch Java Client](https://www.elastic.co/guide/en/elasticsearch/client/java-api-client/current/index.html)
- [Gradle User Guide](https://docs.gradle.org/current/userguide/userguide.html)

---

## ✅ 체크리스트

- [ ] Java 17 설치
- [ ] Gradle 8.5 설치 (또는 Wrapper 사용)
- [ ] Elasticsearch 8.11 실행
- [ ] application.yml 설정
- [ ] 빌드 성공
- [ ] 테스트 통과
- [ ] API 동작 확인
- [ ] SSE 연결 확인
