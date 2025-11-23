package com.ot.security.controller;

import com.ot.security.dto.DashboardStatsDTO;
import com.ot.security.dto.SummaryMetricsDTO;
import com.ot.security.dto.SystemMetricsDTO;
import com.ot.security.repository.ThreatRepository;
import com.ot.security.service.ElasticsearchService;
import com.ot.security.service.SummaryMetricsService;
import com.ot.security.service.SystemMetricsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
@Tag(name = "Dashboard", description = "대시보드 통계 API")
public class DashboardController {

    private final ElasticsearchService elasticsearchService;
    private final SystemMetricsService systemMetricsService;
    private final SummaryMetricsService summaryMetricsService;
    private final ThreatRepository threatRepository;

    @GetMapping("/stats")
    @Operation(summary = "대시보드 통계 조회", description = "전체 시스템 통계 및 실시간 데이터를 조회합니다.")
    public ResponseEntity<DashboardStatsDTO> getDashboardStats() {
        try {
            // 전체 통계
            long totalPackets = elasticsearchService.getTotalPackets();
            long totalThreats = elasticsearchService.getTotalThreats();

            // 최근 5분 통계
            long recentPackets = elasticsearchService.countRecentPackets(5);
            long recentThreats = elasticsearchService.countRecentThreats(5);
            double packetsPerSecond = recentPackets / 300.0;  // 5분 = 300초

            // 집계 데이터
            var threatsByLevel = elasticsearchService.aggregateThreatsByLevel();
            var threatsByType = elasticsearchService.aggregateThreatsByType();
            var packetsByProtocol = elasticsearchService.aggregatePacketsByProtocol();
            var topAttackerIps = elasticsearchService.getTopAttackerIps(5);
            var topTargetIps = elasticsearchService.getTopTargetIps(5);

            // 시스템 메트릭 조회
            SystemMetricsDTO metrics = systemMetricsService.getLatestMetrics();
            SummaryMetricsDTO summaryMetrics = summaryMetricsService.getSummaryMetrics();

            // 시스템 상태 판단
            String systemStatus = "healthy";
            if (recentThreats > 100) {
                systemStatus = "critical";
            } else if (recentThreats > 10) {
                systemStatus = "warning";
            }

            DashboardStatsDTO stats = DashboardStatsDTO.builder()
                .totalPackets(totalPackets)
                .totalThreats(totalThreats)
                .totalBytes(0L)  // TODO: 실제 bytes 집계
                .recentPackets(recentPackets)
                .recentThreats(recentThreats)
                .packetsPerSecond(packetsPerSecond)
                .threatsByLevel(threatsByLevel)
                .threatsByType(threatsByType)
                .packetsByProtocol(packetsByProtocol)
                .topAttackerIps(topAttackerIps)
                .topTargetIps(topTargetIps)
                .systemStatus(systemStatus)
                .cpuUsage(metrics.getCpuUsage())
                .memoryUsage(metrics.getRamUsage())
                .gpuUsage(metrics.getGpuUsage())
                .unconfirmedAlerts(summaryMetrics.getUnconfirmedAlarms())
                .criticalAlerts(summaryMetrics.getCriticalAlarms())
                .safetyScore(summaryMetrics.getSafetyScore())
                .anomalyDay(summaryMetrics.getAnomalyDay())
                .anomalyWeek(summaryMetrics.getAnomalyWeek())
                .newIpCount(summaryMetrics.getNewIpCount())
                .lastUpdate(Instant.now().toString())
                .build();

            return ResponseEntity.ok(stats);

        } catch (IOException e) {
            log.error("대시보드 통계 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/threats/timeline")
    @Operation(summary = "실시간 위협 수 시계열 데이터", description = "24시간 또는 7일간의 시간대별 위협 수를 조회합니다.")
    public ResponseEntity<Map<String, Object>> getThreatTimeline(
            @Parameter(description = "시간 범위 (24h 또는 7d)")
            @RequestParam(defaultValue = "24h") String range
    ) {
        try {
            Instant now = Instant.now();
            List<Map<String, Object>> timeline = new ArrayList<>();

            if ("24h".equals(range)) {
                // 24시간 데이터 (시간별)
                for (int i = 23; i >= 0; i--) {
                    Instant hourStart = now.minus(i, ChronoUnit.HOURS).truncatedTo(ChronoUnit.HOURS);
                    Instant hourEnd = hourStart.plus(1, ChronoUnit.HOURS);

                    long count = threatRepository.countByEventTimestampBetween(hourStart, hourEnd);

                    Map<String, Object> dataPoint = new HashMap<>();
                    dataPoint.put("timestamp", hourStart.toString());
                    dataPoint.put("time", hourStart);
                    dataPoint.put("value", count);
                    timeline.add(dataPoint);
                }
            } else if ("7d".equals(range)) {
                // 7일 데이터 (시간별, 168개 데이터 포인트)
                for (int i = 167; i >= 0; i--) {
                    Instant hourStart = now.minus(i, ChronoUnit.HOURS).truncatedTo(ChronoUnit.HOURS);
                    Instant hourEnd = hourStart.plus(1, ChronoUnit.HOURS);

                    long count = threatRepository.countByEventTimestampBetween(hourStart, hourEnd);

                    Map<String, Object> dataPoint = new HashMap<>();
                    dataPoint.put("timestamp", hourStart.toString());
                    dataPoint.put("time", hourStart);
                    dataPoint.put("value", count);
                    timeline.add(dataPoint);
                }
            }

            Map<String, Object> response = new HashMap<>();
            response.put("range", range);
            response.put("data", timeline);
            response.put("total", timeline.stream().mapToLong(m -> ((Number) m.get("value")).longValue()).sum());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("실시간 위협 수 시계열 데이터 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/threats/top-types")
    @Operation(summary = "위협 유형 Top 5", description = "발생 빈도가 높은 위협 유형 상위 5개를 조회합니다.")
    public ResponseEntity<List<Map<String, Object>>> getTopThreatTypes() {
        try {
            var threatsByType = elasticsearchService.aggregateThreatsByType();

            List<Map<String, Object>> topTypes = new ArrayList<>();
            threatsByType.entrySet().stream()
                    .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                    .limit(5)
                    .forEach(entry -> {
                        Map<String, Object> typeData = new HashMap<>();
                        typeData.put("name", mapThreatTypeName(entry.getKey()));
                        typeData.put("value", entry.getValue());
                        topTypes.add(typeData);
                    });

            return ResponseEntity.ok(topTypes);

        } catch (IOException e) {
            log.error("위협 유형 Top 5 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/threats/by-level")
    @Operation(summary = "위협 등급별 사건 수", description = "최근 7일간 위협 등급별 사건 수를 조회합니다.")
    public ResponseEntity<Map<String, Object>> getThreatsByLevel() {
        try {
            Instant sevenDaysAgo = Instant.now().minus(7, ChronoUnit.DAYS);

            // 최근 7일간 위협 등급별 카운트
            long warningCount = threatRepository.countByThreatLevelAndEventTimestampAfter("warning", sevenDaysAgo);
            long attentionCount = threatRepository.countByThreatLevelAndEventTimestampAfter("attention", sevenDaysAgo);

            // 목적지 자산별 공격 횟수 Top 3
            var topTargetIps = elasticsearchService.getTopTargetIps(3);
            List<Map<String, String>> destinations = new ArrayList<>();
            topTargetIps.forEach((ip, count) -> {
                Map<String, String> dest = new HashMap<>();
                dest.put("ip", ip);
                dest.put("count", String.valueOf(count));
                destinations.add(dest);
            });

            Map<String, Object> response = new HashMap<>();
            response.put("warning", warningCount);  // 긴급
            response.put("attention", attentionCount);  // 경고
            response.put("destinations", destinations);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("위협 등급별 사건 수 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    private String mapThreatTypeName(String type) {
        return switch (type) {
            case "abnormal_protocol" -> "산업 프로토콜 이상 행위";
            case "unauthorized_access" -> "비인가 제어 시스템 접근";
            case "dos_attack" -> "서비스 거부(DoS) 공격";
            case "abnormal_register" -> "비정상 레지스터";
            case "replay_attack" -> "리플레이(Replay) 공격";
            case "port_scan" -> "포트 스캔";
            case "malware" -> "악성코드";
            case "brute_force" -> "무차별 대입";
            default -> type;
        };
    }
}
