package com.ot.security.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ot.security.entity.Threat;
import com.ot.security.entity.XaiAnalysis;
import com.ot.security.repository.ThreatRepository;
import com.ot.security.repository.XaiAnalysisRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class XaiAnalysisControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ThreatRepository threatRepository;

    @Autowired
    private XaiAnalysisRepository xaiAnalysisRepository;

    @BeforeEach
    void cleanDatabase() {
        xaiAnalysisRepository.deleteAll();
        threatRepository.deleteAll();
    }

    @Test
    void receiveXaiAnalysis_shouldInsertRecordAndUpdateThreatType() throws Exception {
        Instant timestamp = Instant.parse("2025-11-10T08:43:40.438249Z");

        Threat threat = Threat.builder()
                .threatId("THREAT-TEST-0001")
                .threatIndex(1500)
                .eventTimestamp(timestamp)
                .detectionEngine("DL")
                .sourceIp("192.168.10.80")
                .destinationIp("192.168.10.47")
                .build();
        threatRepository.save(threat);

        Map<String, Object> analysisDetails = new HashMap<>();
        analysisDetails.put("detection_details", "ML 모델이 Packet 3의 sp 필드를 가장 강하게 의심했습니다.");
        analysisDetails.put("violation", "정상 패턴에서는 sp=502, dp=2004이어야 하나 ...");
        analysisDetails.put("conclusion", "통신 경로 조작이 의심됩니다.");

        Map<String, Object> payload = new HashMap<>();
        payload.put("threat_index", 1);
        payload.put("timestamp", timestamp.toString());
        payload.put("threat_type", "통신 경로 조작 공격");
        payload.put("source_ip", "192.168.10.80");
        payload.put("destination_asset_ip", "192.168.10.47");
        payload.put("detection_engine", "DL-Gemma");
        payload.put("status", "신규");
        payload.put("analysis", analysisDetails);

        String json = objectMapper.writeValueAsString(List.of(payload));

        mockMvc.perform(post("/api/xai/analysis")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk());

        Threat updatedThreat = threatRepository.findById("THREAT-TEST-0001")
                .orElseThrow();
        assertThat(updatedThreat.getThreatType()).isEqualTo("통신 경로 조작 공격");

        List<XaiAnalysis> analyses = xaiAnalysisRepository.findAll();
        assertThat(analyses).hasSize(1);
        XaiAnalysis saved = analyses.get(0);
        assertThat(saved.getThreatIndex()).isEqualTo(1500);
        assertThat(saved.getThreatId()).isEqualTo("THREAT-TEST-0001");
        assertThat(saved.getThreatType()).isEqualTo("통신 경로 조작 공격");
        assertThat(saved.getDetectionDetails()).contains("sp 필드");
    }
}
