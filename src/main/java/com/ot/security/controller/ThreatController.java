package com.ot.security.controller;

import com.ot.security.model.ThreatEvent;
import com.ot.security.service.ElasticsearchService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/threats")
@RequiredArgsConstructor
@Tag(name = "Threats", description = "위협 이벤트 API")
public class ThreatController {

    private final ElasticsearchService elasticsearchService;

    @GetMapping
    @Operation(summary = "위협 이벤트 목록 조회", description = "페이징된 위협 이벤트 목록을 조회합니다.")
    public ResponseEntity<List<ThreatEvent>> getThreats(
        @Parameter(description = "페이지 번호 (0부터 시작)")
        @RequestParam(defaultValue = "0") int page,
        
        @Parameter(description = "페이지 크기")
        @RequestParam(defaultValue = "20") int size
    ) {
        try {
            int from = page * size;
            List<ThreatEvent> threats = elasticsearchService.searchThreats(from, size);
            return ResponseEntity.ok(threats);
        } catch (IOException e) {
            log.error("위협 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
