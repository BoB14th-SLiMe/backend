package com.ot.security.controller;

import com.ot.security.dto.RiskAlarmDTO;
import com.ot.security.entity.Threat;
import com.ot.security.service.ThreatIngestionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/alarms")
@RequiredArgsConstructor
@Tag(name = "Alarm Ingestion", description = "AI PC ML/DL 알람 수신 API")
public class AlarmIngestionController {

    private final ThreatIngestionService threatIngestionService;

    @PostMapping("/{engine}")
    @Operation(summary = "ML/DL 알람 수신", description = "AI-PC에서 전송된 ML/DL 알람을 위협 테이블에 저장합니다. engine 은 ml 또는 dl 이어야 합니다.")
    public ResponseEntity<Threat> ingestAlarm(
            @PathVariable("engine") String engine,
            @RequestBody RiskAlarmDTO payload
    ) {
        try {
            Threat saved = threatIngestionService.ingestRiskAlarm(engine, payload);
            return ResponseEntity.ok(saved);
        } catch (IllegalArgumentException ex) {
            log.warn("알람 수신 실패 - 잘못된 요청", ex);
            return ResponseEntity.badRequest().build();
        } catch (Exception ex) {
            log.error("알람 수신 실패", ex);
            return ResponseEntity.internalServerError().build();
        }
    }
}
