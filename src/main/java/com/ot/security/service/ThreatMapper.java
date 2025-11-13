package com.ot.security.service;

import com.ot.security.entity.Threat;
import com.ot.security.entity.ThreatEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Optional;

/**
 * Converts Threat entities stored in PostgreSQL into the ThreatEvent DTO
 * shape expected by the frontend (Elastic-compatible payload).
 */
@Component
@RequiredArgsConstructor
public class ThreatMapper {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT;

    private final ThreatEnrichmentService threatEnrichmentService;

    public ThreatEvent toThreatEvent(Threat threat) {
        if (threat == null) {
            return null;
        }

        ThreatEvent event = new ThreatEvent();
        event.setThreatId(threat.getThreatId());
        event.setThreatType(Optional.ofNullable(threat.getThreatType()).orElse(""));
        event.setThreatLevel(Optional.ofNullable(threat.getThreatLevel()).orElse("warning"));
        event.setDetectionEngine(Optional.ofNullable(threat.getDetectionEngine()).orElse("RULE"));
        event.setScore(threat.getScore());
        event.setTimestamp(formatTimestamp(threat.getEventTimestamp()));
        event.setSrcIp(threat.getSourceIp());
        event.setDstIp(threat.getDestinationIp());
        event.setStatus(mapStatusForApi(threat.getStatus()));
        event.setSourceAssetName(threat.getSourceAsset());
        event.setTargetAssetName(threat.getDestinationAsset());

        return threatEnrichmentService.enrich(event);
    }

    private String formatTimestamp(Instant instant) {
        return instant == null ? null : ISO_FORMATTER.format(instant);
    }

    private String mapStatusForApi(String status) {
        if (status == null || status.isBlank()) {
            return "new";
        }
        return switch (status.trim()) {
            case "신규", "미작성" -> "new";
            case "확인중", "확인 중" -> "investigating";
            case "조치완료", "완료" -> "completed";
            default -> status.toLowerCase(Locale.ROOT);
        };
    }
}
