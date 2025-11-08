# ============================================
# Spring Boot Backend - Multi-stage Build (Gradle)
# Apple Silicon (M1/M2) 호환 버전
# ============================================

# Stage 1: Build
FROM gradle:8.5-jdk17 AS build

WORKDIR /app

# Gradle 파일 복사 (의존성 캐싱)
COPY build.gradle settings.gradle ./
COPY gradle ./gradle

# 의존성 다운로드 (캐싱 레이어)
RUN gradle dependencies --no-daemon || true

# 소스 코드 복사 및 빌드
COPY src ./src
RUN gradle bootJar --no-daemon

# Stage 2: Runtime
# Alpine 대신 일반 버전 사용 (Apple Silicon 호환)
FROM eclipse-temurin:17-jre

WORKDIR /app

# 빌드 결과물 복사
COPY --from=build /app/build/libs/ot-security-backend.jar app.jar

# 로그 디렉토리 생성
RUN mkdir -p /app/logs

# 비root 사용자 생성
RUN groupadd -r spring && useradd -r -g spring spring
RUN chown -R spring:spring /app
USER spring:spring

# 환경 변수
ENV JAVA_OPTS="-Xms512m -Xmx1024m"
ENV SPRING_PROFILES_ACTIVE=prod

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

# 포트 노출
EXPOSE 8080

# 실행
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
