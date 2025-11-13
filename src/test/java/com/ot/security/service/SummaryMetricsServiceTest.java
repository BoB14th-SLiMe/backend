package com.ot.security.service;

import com.ot.security.dto.AlertSummaryDTO;
import com.ot.security.dto.SummaryMetricsDTO;
import com.ot.security.entity.Threat;
import com.ot.security.entity.XaiAnalysis;
import com.ot.security.repository.AssetRepository;
import com.ot.security.repository.ThreatRepository;
import com.ot.security.repository.XaiAnalysisRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class SummaryMetricsServiceTest {

    @Autowired
    private SummaryMetricsService summaryMetricsService;

    @Autowired
    private ThreatRepository threatRepository;

    @Autowired
    private XaiAnalysisRepository xaiAnalysisRepository;

    @Autowired
    private AssetRepository assetRepository;

    @BeforeEach
    void setUp() {
        xaiAnalysisRepository.deleteAll();
        threatRepository.deleteAll();
        assetRepository.deleteAll();
    }

    @Test
    void getLatestAlerts_returnsLatestNewThreatsFromDatabase() {
        Instant timestamp = Instant.parse("2025-11-10T08:44:04.890520Z");
        Threat threat = threatRepository.save(Threat.builder()
                .threatId("THREAT-DB-01")
                .threatIndex(3000)
                .detectionEngine("DL")
                .eventTimestamp(timestamp)
                .threatType("경로 조작 공격")
                .sourceIp("192.168.10.47")
                .destinationIp("192.168.10.80")
                .threatLevel("warning")
                .status("신규")
                .build());

        xaiAnalysisRepository.save(XaiAnalysis.builder()
                .threatId(threat.getThreatId())
                .threatIndex(threat.getThreatIndex())
                .timestamp(timestamp)
                .detectionDetails("DL engine detected path tampering")
                .violation("Port inversion")
                .conclusion("Investigate communication route")
                .build());

        List<AlertSummaryDTO> alerts = summaryMetricsService.getLatestAlerts(5);

        assertThat(alerts).hasSize(1);
        AlertSummaryDTO alert = alerts.get(0);
        assertThat(alert.getThreatId()).isEqualTo("THREAT-DB-01");
        assertThat(alert.getHasXaiAnalysis()).isTrue();
        assertThat(alert.getDetectionEngine()).isEqualTo("DL");
        assertThat(alert.getSeverity()).isEqualTo("긴급");
    }

    @Test
    void getLatestAlerts_marksAnalysisInProgressWhenThreatTypeMissing() {
        Instant timestamp = Instant.parse("2025-11-10T08:44:04.890520Z");
        threatRepository.save(Threat.builder()
                .threatId("THREAT-DB-03")
                .threatIndex(3002)
                .detectionEngine("DL")
                .eventTimestamp(timestamp)
                .threatType("")
                .sourceIp("192.168.10.47")
                .destinationIp("192.168.10.80")
                .threatLevel("warning")
                .status("신규")
                .build());

        List<AlertSummaryDTO> alerts = summaryMetricsService.getLatestAlerts(1);

        assertThat(alerts).hasSize(1);
        assertThat(alerts.get(0).getHasXaiAnalysis()).isFalse();
        assertThat(alerts.get(0).getThreatType()).isEqualTo("");
    }

    @Test
    void getSummaryMetrics_countsThreatsFromDatabase() {
        Instant timestamp = Instant.now().minusSeconds(600);
        threatRepository.save(Threat.builder()
                .threatId("THREAT-METRIC-01")
                .threatIndex(4000)
                .detectionEngine("DL")
                .eventTimestamp(timestamp)
                .threatType("")
                .sourceIp("10.10.10.10")
                .destinationIp("10.10.10.11")
                .threatLevel("warning")
                .status("신규")
                .build());

        SummaryMetricsDTO dto = summaryMetricsService.getSummaryMetrics();

        assertThat(dto.getAnomalyDay()).isEqualTo(1);
        assertThat(dto.getAnomalyWeek()).isGreaterThanOrEqualTo(1);
        assertThat(dto.getCriticalAlarms()).isEqualTo(1);
        assertThat(dto.getUnconfirmedAlarms()).isEqualTo(1);
        assertThat(dto.getNewIpCount()).isEqualTo(1);
    }
}
