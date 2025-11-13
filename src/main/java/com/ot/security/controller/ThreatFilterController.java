package com.ot.security.controller;

import com.ot.security.dto.AdminActionDTO;
import com.ot.security.dto.PagedResponseDTO;
import com.ot.security.dto.ThreatFilterDTO;
import com.ot.security.entity.ThreatEvent;
import com.ot.security.service.ThreatFilterService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/threats")
@RequiredArgsConstructor
@Tag(name = "Threat Filter", description = "위협 필터링 및 상세 조회 API")
public class ThreatFilterController {

    private final ThreatFilterService threatFilterService;

    /**
     * 위협 필터링 및 검색
     */
    @GetMapping("/filter")
    @Operation(summary = "위협 필터링", description = "심각도, 상태, 날짜, 검색어로 위협을 필터링합니다.")
    public ResponseEntity<PagedResponseDTO<ThreatEvent>> filterThreats(
        @RequestParam(required = false) String severity,
        @RequestParam(required = false) String status,
        @RequestParam(required = false) String startDate,
        @RequestParam(required = false) String endDate,
        @RequestParam(required = false) String search,
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "20") int size,
        @RequestParam(defaultValue = "timestamp,desc") String sort
    ) {
        try {
            ThreatFilterDTO filter = ThreatFilterDTO.builder()
                .severity(severity)
                .status(status)
                .startDate(startDate)
                .endDate(endDate)
                .searchQuery(search)
                .page(page)
                .size(size)
                .sort(sort)
                .build();

            PagedResponseDTO<ThreatEvent> result = threatFilterService.filterThreats(filter);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("위협 필터링 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 위협 상세 조회
     */
    @GetMapping("/{threatId}/detail")
    @Operation(summary = "위협 상세 조회", description = "특정 위협의 상세 정보를 조회합니다.")
    public ResponseEntity<?> getThreatDetail(@PathVariable String threatId) {
        try {
            var detail = threatFilterService.getThreatDetail(threatId);
            return ResponseEntity.ok(detail);
        } catch (Exception e) {
            log.error("위협 상세 조회 실패: {}", threatId, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 관리자 사후조치 작성/수정
     */
    @PostMapping("/{threatId}/admin-action")
    @Operation(summary = "관리자 사후조치", description = "위협에 대한 관리자 사후조치를 작성/수정합니다.")
    public ResponseEntity<?> saveAdminAction(
        @PathVariable String threatId,
        @RequestBody Map<String, Object> actionData
    ) {
        try {
            threatFilterService.saveAdminAction(threatId, actionData);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("사후조치 저장 실패: {}", threatId, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 관리자 사후조치 조회
     */
    @GetMapping("/{threatId}/admin-action")
    @Operation(summary = "관리자 사후조치 조회", description = "위협에 대한 관리자 사후조치 내용을 조회합니다.")
    public ResponseEntity<AdminActionDTO> getAdminAction(@PathVariable String threatId) {
        try {
            AdminActionDTO action = threatFilterService.getAdminAction(threatId);
            if (action == null) {
                return ResponseEntity.noContent().build();
            }
            return ResponseEntity.ok(action);
        } catch (Exception e) {
            log.error("사후조치 조회 실패: {}", threatId, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 위협 타임라인 (24시간/7일)
     */
    @GetMapping("/timeline")
    @Operation(summary = "위협 타임라인", description = "시간대별 위협 발생 통계를 조회합니다.")
    public ResponseEntity<?> getThreatTimeline(
        @RequestParam(defaultValue = "24h") String range
    ) {
        try {
            var timeline = threatFilterService.getThreatTimeline(range);
            return ResponseEntity.ok(timeline);
        } catch (Exception e) {
            log.error("타임라인 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 위협 통계 (Top 5, 등급별)
     */
    @GetMapping("/statistics")
    @Operation(summary = "위협 통계", description = "위협 유형 Top 5와 등급별 통계를 조회합니다.")
    public ResponseEntity<?> getThreatStatistics() {
        try {
            var stats = threatFilterService.getThreatStatistics();
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            log.error("통계 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
