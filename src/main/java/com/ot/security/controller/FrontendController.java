package com.ot.security.controller;

import com.ot.security.service.ElasticsearchService;
import com.ot.security.service.SummaryBannerService;
import com.ot.security.service.ThreatEnrichmentService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@Slf4j
@RestController
@RequestMapping("/api/frontend")
@RequiredArgsConstructor
public class FrontendController {

    private final ElasticsearchService elasticsearchService;
    private final SummaryBannerService summaryBannerService;
    private final ThreatEnrichmentService threatEnrichmentService;

    /**
     * 프론트엔드 배너용 통계 (프론트 형식에 맞춤)
     */
    @GetMapping("/banner/stats")
    public Map<String, Object> getBannerStats() throws Exception {
        return summaryBannerService.buildBannerStats();
    }

    /**
     * 프론트엔드 위협 테이블용 데이터 (프론트 형식에 맞춤)
     */
    @GetMapping("/threats")
    public List<Map<String, Object>> getThreatsForFrontend(
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate,
            @RequestParam(required = false) String grade,
            @RequestParam(required = false) String type
    ) throws Exception {
        var threats = elasticsearchService.searchThreats(0, 100);
        threats.forEach(threatEnrichmentService::enrich);
        
        List<Map<String, Object>> result = new ArrayList<>();
        for (var threat : threats) {
            result.add(Map.of(
                "id", threat.getThreatId(),
                "timestamp", threat.getTimestamp(),
                "grade", mapThreatLevel(threat.getThreatLevel()),
                "type", mapThreatType(threat.getThreatType()),
                "sourceIp", threat.getSrcIp(),
                "destIp", threat.getDstIp(),
                "sourceAsset", threat.getSourceAssetName(),
                "targetAsset", threat.getTargetAssetName(),
                "protocol", threat.getProtocol(),
                "status", mapStatus(threat.getStatus())
            ));
        }
        
        return result;
    }

    private String mapThreatLevel(String level) {
        // 백엔드 레벨을 프론트 형식으로 변환
        return switch (level) {
            case "critical" -> "긴급";
            case "high" -> "높음";
            case "medium" -> "중간";
            default -> "낮음";
        };
    }

    private String mapThreatType(String type) {
        // 백엔드 타입을 프론트 형식으로 변환
        return switch (type) {
            case "dos_attack" -> "DoS 공격";
            case "port_scan" -> "포트 스캔";
            case "malware" -> "악성코드";
            case "brute_force" -> "무차별 대입";
            default -> type;
        };
    }

    private String mapStatus(String status) {
        return switch (status) {
            case "detected" -> "분석중";
            case "investigating" -> "조사중";
            case "resolved" -> "확인";
            default -> status;
        };
    }
}
