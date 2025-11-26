package com.ot.security.service;

import com.ot.security.entity.AdminAction;
import com.ot.security.entity.Threat;
import com.ot.security.entity.XaiAnalysis;
import com.ot.security.repository.AdminActionRepository;
import com.ot.security.repository.ThreatRepository;
import com.ot.security.repository.XaiAnalysisRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class ThreatFilterServiceTest {

    @Autowired
    private ThreatFilterService threatFilterService;

    @Autowired
    private ThreatRepository threatRepository;

    @Autowired
    private XaiAnalysisRepository xaiAnalysisRepository;

    @Autowired
    private AdminActionRepository adminActionRepository;

    @BeforeEach
    void setUp() {
        xaiAnalysisRepository.deleteAll();
        adminActionRepository.deleteAll();
        threatRepository.deleteAll();
    }

    @Test
    void getThreatDetail_includesXaiAnalysisBlockWhenPresent() {
        Instant timestamp = Instant.parse("2025-11-10T08:44:04.890520Z");

        Threat threat = threatRepository.save(Threat.builder()
                .threatId("THREAT-XAI-01")
                .threatIndex(2000)
                .detectionEngine("DL")
                .eventTimestamp(timestamp)
                .sourceIp("192.168.10.47")
                .destinationIp("192.168.10.80")
                .threatType("경로 조작 공격")
                .build());

        XaiAnalysis analysis = XaiAnalysis.builder()
                .threat(threat)
                .detectionDetails("Unauthorized port reversal detected")
                .violation("Source/Destination port inversion")
                .conclusion("Network path tampering suspected")
                .build();
        analysis.setThreat(threat);
        xaiAnalysisRepository.save(analysis);

        Map<String, Object> detail = threatFilterService.getThreatDetail(threat.getThreatId());

        assertThat(detail).containsKey("xai_analysis");
        @SuppressWarnings("unchecked")
        Map<String, Object> xai = (Map<String, Object>) detail.get("xai_analysis");
        assertThat(xai.get("detection")).isEqualTo("Unauthorized port reversal detected");
        assertThat(xai.get("violation")).isEqualTo("Source/Destination port inversion");
        assertThat(xai.get("conclusion")).isEqualTo("Network path tampering suspected");
    }

    @Test
    void saveAdminAction_persistsTimestamps() {
        Instant timestamp = Instant.parse("2025-11-10T08:44:04.890520Z");
        Threat threat = threatRepository.save(Threat.builder()
                .threatId("THREAT-ACTION-01")
                .threatIndex(2002)
                .detectionEngine("DL")
                .eventTimestamp(timestamp)
                .sourceIp("192.168.10.47")
                .destinationIp("192.168.10.80")
                .threatType("경로 조작 공격")
                .build());

        Map<String, Object> payload = new HashMap<>();
        payload.put("status", "completed");
        payload.put("author", "관리자");
        payload.put("content", "조치완료");
        payload.put("completedAt", timestamp.plusSeconds(60).toString());

        threatFilterService.saveAdminAction(threat.getThreatId(), payload);

        AdminAction action = adminActionRepository.findByThreatId(threat.getThreatId())
                .orElseThrow();
        assertThat(action.getStatus()).isEqualTo("completed");
        assertThat(action.getAuthor()).isEqualTo("관리자");
        assertThat(action.getCreatedAt()).isNotNull();
        assertThat(action.getUpdatedAt()).isNotNull();
    }
}
