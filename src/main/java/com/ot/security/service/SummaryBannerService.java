package com.ot.security.service;

import com.ot.security.dto.SummaryMetricsDTO;
import com.ot.security.dto.SystemMetricsDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class SummaryBannerService {

    private final SummaryMetricsService summaryMetricsService;
    private final SystemMetricsService systemMetricsService;

    public Map<String, Object> buildBannerStats() {
        SummaryMetricsDTO summaryMetrics = summaryMetricsService.getSummaryMetrics();
        SystemMetricsDTO metrics = systemMetricsService.getLatestMetrics();
        return composePayload(summaryMetrics, metrics);
    }

    private Map<String, Object> composePayload(SummaryMetricsDTO summaryMetrics, SystemMetricsDTO metrics) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("threat_score", Map.of("score", safeInt(summaryMetrics.getSafetyScore()), "title", "안전 점수"));
        payload.put("anomaly_day", Map.of("number", safeLong(summaryMetrics.getAnomalyDay()), "title", "이상탐지(Day)"));
        payload.put("anomaly_week", Map.of("number", safeLong(summaryMetrics.getAnomalyWeek()), "title", "이상탐지(Week)"));
        payload.put("new_ip", Map.of("number", safeLong(summaryMetrics.getNewIpCount()), "title", "새롭게 탐지된 IP"));
        payload.put("unconfirmed_terminal", Map.of("number", safeLong(summaryMetrics.getUnconfirmedAlarms()), "title", "미확인 알람"));
        payload.put("critical_alert", Map.of("number", safeLong(summaryMetrics.getCriticalAlarms()), "title", "긴급 알람"));
        payload.put("cpu", Map.of("value", roundMetric(metrics.getCpuUsage()), "title", "CPU 사용량"));
        payload.put("ram", Map.of("value", roundMetric(metrics.getRamUsage()), "title", "RAM 사용량"));
        payload.put("gpu", Map.of("value", roundMetric(metrics.getGpuUsage()), "title", "GPU 사용량"));
        return payload;
    }

    private int roundMetric(Double value) {
        if (value == null) {
            return 0;
        }
        return (int) Math.round(value);
    }

    private int safeInt(Integer value) {
        return value == null ? 0 : value;
    }

    private long safeLong(Long value) {
        return value == null ? 0 : value;
    }
}
