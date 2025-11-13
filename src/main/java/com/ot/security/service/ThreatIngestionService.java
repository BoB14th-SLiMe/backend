package com.ot.security.service;

import com.ot.security.dto.RiskAlarmDTO;
import com.ot.security.entity.Threat;
import com.ot.security.repository.ThreatRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class ThreatIngestionService {

    private static final int DEFAULT_INDEX_START = 1000;

    private final ThreatRepository threatRepository;
    private final SSEService sseService;

    @Transactional
    public Threat ingestRiskAlarm(String engine, RiskAlarmDTO dto) {
        validatePayload(engine, dto);

        var risk = dto.getRisk();
        Instant detectedAt = parseTimestamp(risk.getDetected_time());
        String normalizedEngine = normalizeEngine(engine);

        double score = normalizeScore(risk.getScore());
        String threatLevel = determineThreatLevel(score);

        Threat threat = Threat.builder()
                .threatId(generateThreatId(normalizedEngine))
                .threatIndex(nextThreatIndex())
                .detectionEngine(normalizedEngine)
                .eventTimestamp(detectedAt)
                .sourceIp(risk.getSrc_ip())
                .sourceAsset(defaultString(risk.getSrc_asset()))
                .destinationIp(risk.getDst_ip())
                .destinationAsset(defaultString(risk.getDst_asset()))
                .threatType("")
                .threatLevel(threatLevel)
                .status("신규")
                .score(score)
                .build();

        Threat saved = threatRepository.save(threat);

        // 새로운 위협 발생 시 즉시 SSE 전송
        try {
            sseService.sendThreat(saved);
            log.info("새로운 위협을 실시간으로 전송했습니다: {}", saved.getThreatId());
        } catch (Exception e) {
            log.error("SSE 위협 전송 실패", e);
        }

        return saved;
    }

    private void validatePayload(String engine, RiskAlarmDTO dto) {
        if (dto == null || dto.getRisk() == null) {
            throw new IllegalArgumentException("risk payload is required");
        }
        if (!"ML".equalsIgnoreCase(engine) && !"DL".equalsIgnoreCase(engine)) {
            throw new IllegalArgumentException("engine must be ML or DL");
        }
        if (dto.getRisk().getDetected_time() == null) {
            throw new IllegalArgumentException("detected_time is required");
        }
    }

    private Instant parseTimestamp(String timestamp) {
        try {
            return Instant.parse(timestamp);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("detected_time must be ISO-8601 format", e);
        }
    }

    private int nextThreatIndex() {
        return threatRepository.findTopByOrderByThreatIndexDesc()
                .map(t -> t.getThreatIndex() + 1)
                .orElse(DEFAULT_INDEX_START);
    }

    private String generateThreatId(String engine) {
        return engine + "-" + UUID.randomUUID();
    }

    private String normalizeEngine(String engine) {
        return engine == null ? "RULE" : engine.trim().toUpperCase(Locale.ROOT);
    }

    private String defaultString(String value) {
        return value == null ? "" : value;
    }

    private double normalizeScore(Double score) {
        if (score == null) {
            return 0.0;
        }
        if (Double.isNaN(score) || Double.isInfinite(score)) {
            return 0.0;
        }
        if (score < 0) {
            return 0.0;
        }
        return score;
    }

    /**
     * Score 기준으로 위협 수준 결정
     * - score >= 50: warning (긴급)
     * - score < 50: attention (경고)
     */
    private String determineThreatLevel(double score) {
        return score >= 50.0 ? "warning" : "attention";
    }
}
