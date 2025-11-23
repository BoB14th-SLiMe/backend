package com.ot.security.controller;

import com.ot.security.scheduler.DataRetentionScheduler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 데이터 관리 API
 */
@Slf4j
@RestController
@RequestMapping("/api/maintenance")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class DataMaintenanceController {

    private final DataRetentionScheduler dataRetentionScheduler;

    /**
     * 오래된 데이터 수동 삭제
     * GET /api/maintenance/cleanup
     */
    @PostMapping("/cleanup")
    public ResponseEntity<Map<String, Object>> cleanupOldData() {
        log.info("📞 수동 데이터 정리 요청");

        try {
            dataRetentionScheduler.executeManually();

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "데이터 정리 작업이 완료되었습니다.");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("데이터 정리 실패", e);

            Map<String, Object> response = new HashMap<>();
            response.put("success", false);
            response.put("message", "데이터 정리 작업 중 오류가 발생했습니다: " + e.getMessage());

            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * 데이터 보존 정책 조회
     * GET /api/maintenance/retention-policy
     */
    @GetMapping("/retention-policy")
    public ResponseEntity<Map<String, Object>> getRetentionPolicy() {
        Map<String, Object> response = new HashMap<>();
        response.put("retentionDays", 3);
        response.put("description", "3일보다 오래된 트래픽 데이터는 자동으로 삭제됩니다.");
        response.put("scheduledTime", "매일 새벽 2시");

        return ResponseEntity.ok(response);
    }
}
