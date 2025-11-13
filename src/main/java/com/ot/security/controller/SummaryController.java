package com.ot.security.controller;

import com.ot.security.dto.AlertSummaryDTO;
import com.ot.security.dto.SummaryMetricsDTO;
import com.ot.security.service.SummaryMetricsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/summary")
@RequiredArgsConstructor
@Tag(name = "Summary", description = "요약 탭 통계 API")
public class SummaryController {

    private final SummaryMetricsService summaryMetricsService;

    @GetMapping("/metrics")
    @Operation(summary = "요약 지표 조회", description = "요약관리 탭에 필요한 핵심 통계를 반환합니다.")
    public ResponseEntity<SummaryMetricsDTO> getSummaryMetrics() {
        return ResponseEntity.ok(summaryMetricsService.getSummaryMetrics());
    }

    @PutMapping("/metrics")
    @Operation(summary = "요약 지표 수동 업데이트", description = "수동으로 요약 지표 값을 설정하고 자동 갱신 여부를 변경합니다.")
    public ResponseEntity<SummaryMetricsDTO> updateSummaryMetrics(@RequestBody SummaryMetricsDTO dto) {
        try {
            return ResponseEntity.ok(summaryMetricsService.updateSummaryMetrics(dto));
        } catch (Exception e) {
            log.error("요약 지표 수동 업데이트 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/alerts")
    @Operation(summary = "요약 알림 조회", description = "요약관리 탭의 이상 탐지 및 알람 목록을 조회합니다.")
    public ResponseEntity<List<AlertSummaryDTO>> getSummaryAlerts(
            @RequestParam(defaultValue = "5") int limit
    ) {
        int safeLimit = Math.min(Math.max(1, limit), 20);
        return ResponseEntity.ok(summaryMetricsService.getLatestAlerts(safeLimit));
    }
}
