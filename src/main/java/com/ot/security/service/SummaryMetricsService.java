package com.ot.security.service;

import com.ot.security.dto.AlertSummaryDTO;
import com.ot.security.dto.SummaryMetricsDTO;
import com.ot.security.entity.SummaryMetrics;
import com.ot.security.entity.Threat;
import com.ot.security.entity.ThreatEvent;
import com.ot.security.repository.AssetRepository;
import com.ot.security.repository.SummaryMetricsRepository;
import com.ot.security.repository.ThreatRepository;
import com.ot.security.repository.XaiAnalysisRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class SummaryMetricsService {

    private static final int DAY_MINUTES = 60 * 24;
    private static final int WEEK_MINUTES = DAY_MINUTES * 7;
    private static final List<String> NEW_STATUS_KEYS = List.of("신규", "new");

    private final ThreatRepository threatRepository;
    private final AssetRepository assetRepository;
    private final SummaryMetricsRepository summaryMetricsRepository;
    private final ThreatMapper threatMapper;
    private final XaiAnalysisRepository xaiAnalysisRepository;
    private final ElasticsearchService elasticsearchService;

    @Transactional
    public SummaryMetricsDTO computeAndStoreMetrics() {
        SummaryMetrics entity = ensureSummaryMetrics();
        SummaryMetricsDTO snapshot = buildMetricsSnapshot();
        applySnapshot(entity, snapshot);
        entity.setUpdatedAt(Instant.now());
        summaryMetricsRepository.save(entity);
        return snapshot;
    }

    public SummaryMetricsDTO getSummaryMetrics() {
        SummaryMetrics entity = ensureSummaryMetrics();
        SummaryMetricsDTO snapshot = buildMetricsSnapshot();
        applySnapshot(entity, snapshot);
        entity.setUpdatedAt(Instant.now());
        summaryMetricsRepository.save(entity);
        return snapshot;
    }

    public List<AlertSummaryDTO> getLatestAlerts(int limit) {
        int safeLimit = Math.min(Math.max(limit, 1), 20);
        Pageable pageable = PageRequest.of(0, safeLimit, Sort.by(Sort.Direction.DESC, "eventTimestamp"));
        Page<Threat> page = threatRepository.findByStatusInIgnoreCase(
                NEW_STATUS_KEYS.stream().map(String::toLowerCase).collect(Collectors.toUnmodifiableList()),
                pageable
        );

        List<AlertSummaryDTO> alerts = new ArrayList<>();
        for (Threat threat : page.getContent()) {
            ThreatEvent event = threatMapper.toThreatEvent(threat);

            // XAI 분석 데이터가 실제로 존재하는지 확인
            boolean hasXaiAnalysis = xaiAnalysisRepository
                    .findTop1ByThreatIdOrderByTimestampDesc(threat.getThreatId())
                    .isPresent();

            alerts.add(AlertSummaryDTO.builder()
                    .threatId(event.getThreatId())
                    .timestamp(event.getTimestamp())
                    .severity(mapSeverity(event.getThreatLevel()))
                    .status(mapStatus(event.getStatus()))
                    .detectionEngine(mapDetectionEngine(event.getDetectionEngine()))
                    .sourceIp(event.getSrcIp())
                    .sourceAsset(event.getSourceAssetName())
                    .targetIp(event.getDstIp())
                    .targetAsset(event.getTargetAssetName())
                    .threatType(event.getThreatType())
                    .hasXaiAnalysis(hasXaiAnalysis)
                    .build());
        }
        return alerts;
    }

    private SummaryMetricsDTO buildMetricsSnapshot() {
        Instant now = Instant.now();
        Instant daySince = now.minus(DAY_MINUTES, ChronoUnit.MINUTES);
        Instant weekSince = now.minus(WEEK_MINUTES, ChronoUnit.MINUTES);

        long dayThreats = threatRepository.countByEventTimestampAfter(daySince);
        long weekThreats = threatRepository.countByEventTimestampAfter(weekSince);

        long unconfirmed = threatRepository.countByStatusInIgnoreCase(NEW_STATUS_KEYS);
        long criticalAlerts = threatRepository.countByThreatLevelAndStatusInIgnoreCase("warning", NEW_STATUS_KEYS);
        long warningAlerts = threatRepository.countByThreatLevelAndStatusInIgnoreCase("attention", NEW_STATUS_KEYS);

        Set<String> recentIps = threatRepository.findDistinctSourceIpSince(daySince).stream()
                .filter(ip -> ip != null && !ip.isBlank())
                .filter(ip -> assetRepository.findByIpAddress(ip).isEmpty())
                .collect(Collectors.toSet());

        // 위협 점수 계산: Elasticsearch에서 신규 상태 threat의 score 합산
        int riskScore = calculateThreatScoreSum();

        return SummaryMetricsDTO.builder()
                .safetyScore(riskScore)
                .anomalyDay(dayThreats)
                .anomalyWeek(weekThreats)
                .newIpCount((long) recentIps.size())
                .unconfirmedAlarms(unconfirmed)
                .criticalAlarms(criticalAlerts)
                .build();
    }

    @Transactional
    public SummaryMetricsDTO updateSummaryMetrics(SummaryMetricsDTO dto) {
        SummaryMetrics entity = ensureSummaryMetrics();

        if (dto.getSafetyScore() != null) entity.setSafetyScore(dto.getSafetyScore());
        if (dto.getAnomalyDay() != null) entity.setAnomalyDay(dto.getAnomalyDay());
        if (dto.getAnomalyWeek() != null) entity.setAnomalyWeek(dto.getAnomalyWeek());
        if (dto.getNewIpCount() != null) entity.setNewIpCount(dto.getNewIpCount());
        if (dto.getUnconfirmedAlarms() != null) entity.setUnconfirmedAlarms(dto.getUnconfirmedAlarms());
        if (dto.getCriticalAlarms() != null) entity.setCriticalAlarms(dto.getCriticalAlarms());

        if (dto.getAutoRefresh() != null) {
            entity.setAutoRefresh(dto.getAutoRefresh());
        }

        entity.setUpdatedAt(Instant.now());
        summaryMetricsRepository.save(entity);
        return toDTO(entity);
    }

    private SummaryMetrics ensureSummaryMetrics() {
        return summaryMetricsRepository.findById(1L)
                .orElseGet(() -> summaryMetricsRepository.save(
                        SummaryMetrics.builder()
                                .id(1L)
                                .updatedAt(Instant.now())
                                .build()
                ));
    }
    private void applySnapshot(SummaryMetrics entity, SummaryMetricsDTO snapshot) {
        entity.setSafetyScore(snapshot.getSafetyScore());
        entity.setAnomalyDay(snapshot.getAnomalyDay());
        entity.setAnomalyWeek(snapshot.getAnomalyWeek());
        entity.setNewIpCount(snapshot.getNewIpCount());
        entity.setUnconfirmedAlarms(snapshot.getUnconfirmedAlarms());
        entity.setCriticalAlarms(snapshot.getCriticalAlarms());
    }

    private SummaryMetricsDTO toDTO(SummaryMetrics entity) {
        return SummaryMetricsDTO.builder()
                .safetyScore(entity.getSafetyScore())
                .anomalyDay(entity.getAnomalyDay())
                .anomalyWeek(entity.getAnomalyWeek())
                .newIpCount(entity.getNewIpCount())
                .unconfirmedAlarms(entity.getUnconfirmedAlarms())
                .criticalAlarms(entity.getCriticalAlarms())
                .autoRefresh(entity.getAutoRefresh())
                .build();
    }

    /**
     * 위협점수 계산: Elasticsearch에서 신규 상태 threat의 score 합산
     * - 최대 100점으로 제한
     *
     * @return 위협점수 (0-100)
     */
    private int calculateThreatScoreSum() {
        try {
            log.info("위협 점수 계산 시작");
            // Elasticsearch에서 모든 위협을 가져와서 신규 상태만 필터링
            List<ThreatEvent> threats = elasticsearchService.searchThreats(0, 1000);
            log.info("조회된 총 위협 수: {}", threats.size());

            double totalScore = threats.stream()
                    .filter(threat -> {
                        String status = threat.getStatus();
                        boolean isNew = status != null && NEW_STATUS_KEYS.contains(status.toLowerCase());
                        if (isNew) {
                            log.debug("신규 위협 발견: ID={}, status={}, score={}", threat.getThreatId(), status, threat.getScore());
                        }
                        return isNew;
                    })
                    .mapToDouble(threat -> threat.getScore() != null ? threat.getScore() : 0.0)
                    .sum();

            log.info("신규 위협 점수 합계: {}", totalScore);

            // 100점 만점으로 제한
            int finalScore = (int) Math.min(100, Math.max(0, totalScore));
            log.info("최종 위협 점수: {}", finalScore);
            return finalScore;
        } catch (Exception e) {
            log.error("위협 점수 계산 실패", e);
            return 0;
        }
    }

    private String mapSeverity(String threatLevel) {
        if (threatLevel == null) {
            return "경고";
        }
        return switch (threatLevel.toLowerCase()) {
            case "warning" -> "긴급";
            case "attention" -> "경고";
            default -> "경고";
        };
    }

    private String mapStatus(String status) {
        if (status == null) {
            return "신규";
        }
        return switch (status) {
            case "resolved", "completed" -> "조치완료";
            case "investigating" -> "확인중";
            default -> "신규";
        };
    }

    private String mapDetectionEngine(String detectionEngine) {
        if (detectionEngine == null) {
            return "RULE";
        }
        return detectionEngine.toUpperCase();
    }
}
