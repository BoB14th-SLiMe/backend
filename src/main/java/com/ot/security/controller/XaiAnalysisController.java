package com.ot.security.controller;

import com.ot.security.dto.XaiAnalysisDTO;
import com.ot.security.service.XaiAnalysisService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/xai")
@RequiredArgsConstructor
@Tag(name = "XAI", description = "XAI 분석 결과 수신 API")
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
}