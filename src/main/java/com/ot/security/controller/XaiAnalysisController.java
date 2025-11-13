package com.ot.security.controller;

import com.ot.security.dto.XaiAnalysisDTO;
import com.ot.security.entity.XaiAnalysis;
import com.ot.security.service.XaiAnalysisService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/xai")
@RequiredArgsConstructor
@Tag(name = "XAI", description = "XAI 분석 결과 API")
public class XaiAnalysisController {

    private final XaiAnalysisService xaiAnalysisService;

    @PostMapping("/analysis")
    @Operation(summary = "XAI 분석 결과 수신", description = "AI PC로부터 XAI 분석 결과를 JSON 배열로 수신하여 저장합니다.")
    public ResponseEntity<Void> receiveXaiAnalysis(@RequestBody List<XaiAnalysisDTO> analysisList) {
        try {
            xaiAnalysisService.saveXaiAnalyses(analysisList);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("XAI 분석 결과 처리 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/analyses")
    @Operation(summary = "XAI 분석 목록 조회", description = "저장된 XAI 분석 결과를 페이징하여 조회합니다.")
    public ResponseEntity<Page<XaiAnalysis>> getAnalyses(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        try {
            Pageable pageable = PageRequest.of(page, size);
            Page<XaiAnalysis> analyses = xaiAnalysisService.getAllAnalyses(pageable);
            return ResponseEntity.ok(analyses);
        } catch (Exception e) {
            log.error("XAI 분석 목록 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/analyses/recent")
    @Operation(summary = "최근 XAI 분석 조회", description = "최근 10건의 XAI 분석 결과를 조회합니다.")
    public ResponseEntity<List<XaiAnalysis>> getRecentAnalyses() {
        try {
            List<XaiAnalysis> analyses = xaiAnalysisService.getRecentAnalyses();
            return ResponseEntity.ok(analyses);
        } catch (Exception e) {
            log.error("최근 XAI 분석 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PostMapping("/generate-dummy")
    @Operation(summary = "더미 데이터 생성", description = "프로토타입용 더미 XAI 분석 데이터를 생성합니다.")
    public ResponseEntity<Void> generateDummyData(@RequestParam(defaultValue = "20") int count) {
        try {
            xaiAnalysisService.generateDummyData(count);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("더미 데이터 생성 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}