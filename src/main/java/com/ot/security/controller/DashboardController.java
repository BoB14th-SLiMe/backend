package com.ot.security.controller;

import com.ot.security.dto.DashboardStatsDTO;
import com.ot.security.service.ElasticsearchService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Instant;

@Slf4j
@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
@Tag(name = "Dashboard", description = "대시보드 통계 API")
public class DashboardController {

    private final ElasticsearchService elasticsearchService;

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
                .cpuUsage(0.0)   // TODO: 실제 시스템 메트릭
                .memoryUsage(0.0)
                .lastUpdate(Instant.now().toString())
                .build();
            
            return ResponseEntity.ok(stats);
            
        } catch (IOException e) {
            log.error("대시보드 통계 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
