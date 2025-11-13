package com.ot.security.service;

import com.ot.security.entity.Asset;
import com.ot.security.entity.ThreatEvent;
import com.ot.security.repository.AssetRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;

/**
 * 위협 이벤트에 자산 매핑과 표현 규칙을 적용한다.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ThreatEnrichmentService {

    private static final List<String> SUPPORTED_ENGINES = List.of("ML", "DL", "RULE");

    private final AssetRepository assetRepository;

    public ThreatEvent enrich(ThreatEvent threat) {
        if (threat == null) {
            return null;
        }

        normalizeStatus(threat);
        normalizeDetectionEngine(threat);
        normalizeThreatLevel(threat);
        attachAssetMetadata(threat);

        return threat;
    }

    private void normalizeStatus(ThreatEvent threat) {
        String status = threat.getStatus();
        if (status == null || status.isBlank()) {
            threat.setStatus("new");
            return;
        }

        String normalized = switch (status.toLowerCase(Locale.ROOT)) {
            case "detected", "new" -> "new";
            case "investigating", "in_progress", "checking" -> "investigating";
            case "resolved", "completed", "done" -> "completed";
            default -> "new";
        };
        threat.setStatus(normalized);
    }

    private void normalizeDetectionEngine(ThreatEvent threat) {
        String engine = threat.getDetectionEngine();
        if (engine == null || engine.isBlank()) {
            threat.setDetectionEngine("RULE");
            return;
        }

        String upper = engine.trim().toUpperCase(Locale.ROOT);
        threat.setDetectionEngine(
                SUPPORTED_ENGINES.contains(upper) ? upper : "RULE"
        );
    }

    private void normalizeThreatLevel(ThreatEvent threat) {
        String level = threat.getThreatLevel();
        if (level == null) {
            threat.setThreatLevel("warning");
            return;
        }
        threat.setThreatLevel(level.equalsIgnoreCase("critical") ? "critical" : "warning");
    }

    private void attachAssetMetadata(ThreatEvent threat) {
        findAssetByIp(threat.getSrcIp()).ifPresent(asset -> {
            threat.setSourceAssetName(asset.getName());
            threat.setSourceAssetNote(asset.getAssetType());
        });
        findAssetByIp(threat.getDstIp()).ifPresent(asset ->
                threat.setTargetAssetName(asset.getName()));
    }

    private java.util.Optional<Asset> findAssetByIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return java.util.Optional.empty();
        }
        return assetRepository.findByIpAddress(ip.trim());
    }
}
