package com.ot.security.controller;

import com.ot.security.repository.AssetRepository;
import com.ot.security.service.ElasticsearchService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/traffic")
@RequiredArgsConstructor
@Tag(name = "Traffic", description = "트래픽 모니터링 API")
public class TrafficController {

    private final ElasticsearchService elasticsearchService;
    private final AssetRepository assetRepository;

    @GetMapping("/monitoring")
    @Operation(summary = "트래픽 모니터링 데이터 조회", description = "24시간 트래픽 데이터와 7일 평균 데이터를 조회합니다.")
    public ResponseEntity<Map<String, Object>> getTrafficMonitoring() {
        try {
            Map<String, Object> response = new HashMap<>();

            // 24시간 트래픽 데이터
            List<Map<String, Object>> currentTraffic = elasticsearchService.getHourlyTrafficData();

            // 24시간 위협 데이터
            List<Map<String, Object>> threatData = elasticsearchService.getHourlyThreatData();

            // 7일 평균 트래픽 데이터
            List<Map<String, Object>> averageTraffic = elasticsearchService.getWeeklyAverageTraffic();

            response.put("current", currentTraffic);
            response.put("threats", threatData);
            response.put("average", averageTraffic);

            return ResponseEntity.ok(response);
        } catch (IOException e) {
            log.error("트래픽 모니터링 데이터 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/hourly")
    @Operation(summary = "시간대별 트래픽 조회", description = "최근 24시간 시간대별 트래픽 데이터를 조회합니다.")
    public ResponseEntity<List<Map<String, Object>>> getHourlyTraffic() {
        log.info("=== 시간대별 트래픽 API 호출됨 ===");
        try {
            List<Map<String, Object>> data = elasticsearchService.getHourlyTrafficData();
            log.info("트래픽 데이터 반환: {} 건", data.size());
            return ResponseEntity.ok(data);
        } catch (IOException e) {
            log.error("시간대별 트래픽 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/average")
    @Operation(summary = "7일 평균 트래픽 조회", description = "최근 7일간의 시간대별 평균 트래픽 데이터를 조회합니다.")
    public ResponseEntity<List<Map<String, Object>>> getAverageTraffic() {
        try {
            List<Map<String, Object>> data = elasticsearchService.getWeeklyAverageTraffic();
            return ResponseEntity.ok(data);
        } catch (IOException e) {
            log.error("7일 평균 트래픽 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/network-stats")
    @Operation(summary = "네트워크 통계 조회", description = "현재 네트워크 연결 수와 PPS를 조회합니다.")
    public ResponseEntity<Map<String, Object>> getNetworkStats() {
        try {
            // 최근 60초 동안의 평균 PPS 계산 (더 안정적인 값)
            long recentPackets = elasticsearchService.countPacketsBetweenSeconds(60, 0);
            double pps = recentPackets / 60.0; // 60초로 나누어 초당 패킷 수 계산

            long connections = assetRepository.countByAssetTypeInAndIsVisibleTrue(List.of("hmi", "plc"));

            log.info("네트워크 통계 - 총 패킷: {}, PPS: {}, 연결: {}", recentPackets, pps, connections);

            Map<String, Object> stats = new HashMap<>();
            stats.put("packetsPerSecond", Math.round(pps * 100.0) / 100.0);
            stats.put("connections", connections);

            return ResponseEntity.ok(stats);
        } catch (IOException e) {
            log.error("네트워크 통계 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
