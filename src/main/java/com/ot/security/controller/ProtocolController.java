package com.ot.security.controller;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/protocols")
@RequiredArgsConstructor
@Tag(name = "Protocol", description = "프로토콜 분포 통계 API")
public class ProtocolController {

    private final ElasticsearchService elasticsearchService;

    @GetMapping("/hourly")
    @Operation(summary = "1시간 프로토콜 분포", description = "최근 1시간 동안의 프로토콜별 패킷 분포를 조회합니다.")
    public ResponseEntity<Map<String, Object>> getHourlyProtocolDistribution() {
        try {
            // Elasticsearch에서 프로토콜별 집계
            Map<String, Long> protocolStats = elasticsearchService.aggregatePacketsByProtocol();

            // 전체 패킷 수 계산
            long totalPackets = protocolStats.values().stream().mapToLong(Long::longValue).sum();

            Map<String, Object> response = new HashMap<>();
            response.put("protocols", protocolStats);
            response.put("total", totalPackets);
            response.put("period", "1h");

            return ResponseEntity.ok(response);

        } catch (IOException e) {
            log.error("1시간 프로토콜 분포 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/weekly")
    @Operation(summary = "7일간 프로토콜 분포", description = "최근 7일간의 일별 프로토콜 분포를 조회합니다.")
    public ResponseEntity<Map<String, Object>> getWeeklyProtocolDistribution() {
        try {
            List<Map<String, Object>> weeklyData = elasticsearchService.getWeeklyProtocolDistribution();
            if (weeklyData == null || weeklyData.isEmpty()) {
                return ResponseEntity.ok(Map.of(
                        "mode", "dummy",
                        "data", generateWeeklyProtocolDummy()
                ));
            }

            return ResponseEntity.ok(Map.of(
                    "mode", "real",
                    "data", weeklyData
            ));

        } catch (IOException e) {
            log.error("7일간 프로토콜 분포 조회 실패", e);
            return ResponseEntity.ok(Map.of(
                    "mode", "dummy",
                    "data", generateWeeklyProtocolDummy()
            ));
        }
    }

    private List<Map<String, Object>> generateWeeklyProtocolDummy() {
        return List.of(
                buildDummyDay("2025-11-10", new long[]{7800, 2100, 600, 300}),
                buildDummyDay("2025-11-11", new long[]{8000, 1900, 620, 280}),
                buildDummyDay("2025-11-12", new long[]{7900, 2000, 580, 290}),
                buildDummyDay("2025-11-13", new long[]{8050, 2050, 610, 270}),
                buildDummyDay("2025-11-14", new long[]{7950, 1980, 600, 260}),
                buildDummyDay("2025-11-15", new long[]{8020, 2100, 590, 280}),
                buildDummyDay("2025-11-16", new long[]{7980, 2150, 620, 300})
        );
    }

    private Map<String, Object> buildDummyDay(String date, long[] values) {
        Map<String, Long> protocols = new HashMap<>();
        protocols.put("Modbus", values[0]);
        protocols.put("TCP", values[1]);
        protocols.put("UDP", values[2]);
        protocols.put("LLDP", values[3]);

        Map<String, Object> day = new HashMap<>();
        day.put("date", date);
        day.put("protocols", protocols);
        day.put("total", values[0] + values[1] + values[2] + values[3]);
        return day;
    }
}
