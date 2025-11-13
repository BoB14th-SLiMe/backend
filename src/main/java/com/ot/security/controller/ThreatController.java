package com.ot.security.controller;

import com.ot.security.entity.Threat;
import com.ot.security.entity.ThreatEvent;
import com.ot.security.repository.ThreatRepository;
import com.ot.security.service.ThreatMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api/threats")
@RequiredArgsConstructor
@Tag(name = "Threats", description = "위협 이벤트 API")
public class ThreatController {

    private final ThreatRepository threatRepository;
    private final ThreatMapper threatMapper;

    @GetMapping
    @Operation(summary = "위협 이벤트 목록 조회", description = "페이징된 위협 이벤트 목록을 조회합니다.")
    public ResponseEntity<List<ThreatEvent>> getThreats(
        @Parameter(description = "페이지 번호 (0부터 시작)")
        @RequestParam(defaultValue = "0") int page,
        
        @Parameter(description = "페이지 크기")
        @RequestParam(defaultValue = "20") int size
    ) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.min(Math.max(size, 1), 100);
        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.ASC, "eventTimestamp"));

        Page<Threat> threatsPage = threatRepository.findAll(pageable);
        List<ThreatEvent> threats = threatsPage
                .getContent()
                .stream()
                .map(threatMapper::toThreatEvent)
                .collect(Collectors.toList());

        return ResponseEntity.ok(threats);
    }

    @GetMapping("/latest")
    @Operation(summary = "최신 위협 목록", description = "요약 대시보드용 최신 위협 이벤트를 조회합니다.")
    public ResponseEntity<List<ThreatEvent>> getLatestThreats(
            @RequestParam(defaultValue = "5") int limit
    ) {
        int safeLimit = Math.min(Math.max(limit, 1), 50);
        Pageable pageable = PageRequest.of(0, safeLimit, Sort.by(Sort.Direction.DESC, "eventTimestamp"));

        Page<Threat> threatsPage = threatRepository.findAll(pageable);
        List<ThreatEvent> threats = threatsPage
                .getContent()
                .stream()
                .map(threatMapper::toThreatEvent)
                .collect(Collectors.toList());

        return ResponseEntity.ok(threats);
    }

    @PatchMapping("/{threatId}/status")
    @Operation(summary = "위협 상태 업데이트", description = "위협의 상태를 업데이트합니다.")
    public ResponseEntity<Void> updateThreatStatus(
            @PathVariable String threatId,
            @RequestParam String status
    ) {
        Threat threat = threatRepository.findById(threatId)
                .orElseThrow(() -> new RuntimeException("위협을 찾을 수 없습니다: " + threatId));

        // Map English status to Korean for consistency
        String mappedStatus = mapStatusToKorean(status);
        threat.setStatus(mappedStatus);
        threatRepository.save(threat);

        log.info("위협 상태 업데이트: {} -> {} ({})", threatId, status, mappedStatus);
        return ResponseEntity.ok().build();
    }

    private String mapStatusToKorean(String status) {
        if (status == null) {
            return "신규";
        }
        return switch (status.toLowerCase()) {
            case "new", "detected" -> "신규";
            case "investigating" -> "확인중";
            case "completed", "resolved" -> "조치완료";
            case "false_positive" -> "오탐";
            default -> status; // Keep original if not matched
        };
    }
}
