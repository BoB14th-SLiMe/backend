package com.ot.security.controller;

import com.ot.security.dto.SystemMetricsDTO;
import com.ot.security.service.SystemMetricsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/metrics")
@RequiredArgsConstructor
@Tag(name = "System Metrics", description = "시스템 리소스 메트릭 API")
public class SystemMetricsController {

    private final SystemMetricsService systemMetricsService;

    @PostMapping("/system")
    @Operation(summary = "시스템 메트릭 수신", description = "AI PC로부터 시스템 리소스 사용량을 수신합니다.")
    public ResponseEntity<Void> receiveMetrics(@RequestBody SystemMetricsDTO dto) {
        try {
            systemMetricsService.saveMetrics(dto);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("시스템 메트릭 저장 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/system/latest")
    @Operation(summary = "최신 메트릭 조회", description = "가장 최근의 시스템 리소스 사용량을 조회합니다.")
    public ResponseEntity<SystemMetricsDTO> getLatestMetrics() {
        try {
            SystemMetricsDTO metrics = systemMetricsService.getLatestMetrics();
            return ResponseEntity.ok(metrics);
        } catch (Exception e) {
            log.error("최신 메트릭 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/system/average")
    @Operation(summary = "평균 메트릭 조회", description = "지정된 기간 동안의 평균 시스템 리소스 사용량을 조회합니다.")
    public ResponseEntity<SystemMetricsDTO> getAverageMetrics(@RequestParam(defaultValue = "60") int minutes) {
        try {
            SystemMetricsDTO metrics = systemMetricsService.getAverageMetrics(minutes);
            return ResponseEntity.ok(metrics);
        } catch (Exception e) {
            log.error("평균 메트릭 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/system/generate-dummy")
    @Operation(summary = "더미 메트릭 생성", description = "프로토타입용 더미 시스템 메트릭을 생성합니다.")
    public ResponseEntity<Void> generateDummyMetrics() {
        try {
            systemMetricsService.generateDummyMetrics();
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("더미 메트릭 생성 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
