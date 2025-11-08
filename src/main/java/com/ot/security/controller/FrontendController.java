package com.ot.security.controller;

import com.ot.security.service.ElasticsearchService;
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

    /**
     * 프론트엔드 배너용 통계 (프론트 형식에 맞춤)
     */
    @GetMapping("/banner/stats")
    public Map<String, Object> getBannerStats() throws Exception {
        long recentThreatsDay = elasticsearchService.countRecentThreats(1440); // 24시간
        long recentThreatsWeek = elasticsearchService.countRecentThreats(10080); // 7일
        
        return Map.of(
            "threat_score", Map.of("score", calculateThreatScore(), "title", "위협 점수"),
            "anomaly_day", Map.of("number", recentThreatsDay, "title", "이상탐지(Day)"),
            "anomaly_week", Map.of("number", recentThreatsWeek, "title", "이상탐지(Week)"),
            "new_ip", Map.of("number", 0, "title", "새롭게 탐지된 IP"),
            "unconfirmed_terminal", Map.of("number", 1, "title", "미확인 알람"),
            "critical_alert", Map.of("number", getUnresolvedCriticalCount(), "title", "긴급 알람"),
            "cpu", Map.of("value", 25, "title", "CPU 사용량"),
            "ram", Map.of("value", 67, "title", "RAM 사용량"),
            "gpu", Map.of("value", 33, "title", "GPU 사용량")
        );
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
        
        List<Map<String, Object>> result = new ArrayList<>();
        for (var threat : threats) {
            result.add(Map.of(
                "id", threat.getThreatId(),
                "timestamp", threat.getTimestamp(),
                "grade", mapThreatLevel(threat.getThreatLevel()),
                "type", mapThreatType(threat.getThreatType()),
                "sourceIp", threat.getSrcIp(),
                "destIp", threat.getDstIp(),
                "protocol", threat.getProtocol(),
                "status", mapStatus(threat.getStatus())
            ));
        }
        
        return result;
    }

    private int calculateThreatScore() throws Exception {
        // 위협 점수 계산 로직
        long critical = elasticsearchService.countRecentThreats(60);
        return (int) Math.min(100, critical * 2);
    }

    private long getUnresolvedCriticalCount() throws Exception {
        // 미해결 긴급 위협 카운트
        return elasticsearchService.countRecentThreats(1440);
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