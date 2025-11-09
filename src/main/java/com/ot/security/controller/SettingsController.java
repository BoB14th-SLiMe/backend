package com.ot.security.controller;

import com.ot.security.dto.*;
import com.ot.security.service.SettingsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/settings")
@RequiredArgsConstructor
@Tag(name = "Settings", description = "시스템 설정 API")
public class SettingsController {

    private final SettingsService settingsService;

    /**
     * 시스템 설정 조회
     */
    @GetMapping("/system")
    @Operation(summary = "시스템 설정 조회", description = "자동 갱신 주기, 데이터 보관 기간, 임계값 등을 조회합니다.")
    public ResponseEntity<SystemSettingsDTO> getSystemSettings() {
        try {
            SystemSettingsDTO settings = settingsService.getSystemSettings();
            return ResponseEntity.ok(settings);
        } catch (Exception e) {
            log.error("시스템 설정 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 시스템 설정 업데이트
     */
    @PutMapping("/system")
    @Operation(summary = "시스템 설정 업데이트", description = "시스템 설정을 업데이트합니다.")
    public ResponseEntity<SystemSettingsDTO> updateSystemSettings(@RequestBody SystemSettingsDTO dto) {
        try {
            SystemSettingsDTO updated = settingsService.updateSystemSettings(dto);
            return ResponseEntity.ok(updated);
        } catch (Exception e) {
            log.error("시스템 설정 업데이트 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 배너 설정 조회
     */
    @GetMapping("/banner-config")
    @Operation(summary = "배너 설정 조회", description = "활성화된 배너 메트릭과 비활성화된 메트릭을 조회합니다.")
    public ResponseEntity<BannerConfigDTO> getBannerConfig() {
        try {
            BannerConfigDTO config = settingsService.getBannerConfig();
            return ResponseEntity.ok(config);
        } catch (Exception e) {
            log.error("배너 설정 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 배너 설정 업데이트
     */
    @PutMapping("/banner-config")
    @Operation(summary = "배너 설정 업데이트", description = "배너 메트릭의 활성화 여부와 순서를 업데이트합니다.")
    public ResponseEntity<Void> updateBannerConfig(@RequestBody BannerConfigDTO dto) {
        try {
            settingsService.updateBannerConfig(dto);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("배너 설정 업데이트 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 토폴로지 설정 조회
     */
    @GetMapping("/topology")
    @Operation(summary = "토폴로지 설정 조회", description = "네트워크 토폴로지의 자산 배치 정보를 조회합니다.")
    public ResponseEntity<TopologyConfigDTO> getTopologyConfig() {
        try {
            TopologyConfigDTO config = settingsService.getTopologyConfig();
            return ResponseEntity.ok(config);
        } catch (Exception e) {
            log.error("토폴로지 설정 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 토폴로지 설정 업데이트
     */
    @PutMapping("/topology")
    @Operation(summary = "토폴로지 설정 업데이트", description = "자산의 위치와 가시성을 업데이트합니다.")
    public ResponseEntity<Void> updateTopologyConfig(@RequestBody TopologyConfigDTO dto) {
        try {
            settingsService.updateTopologyConfig(dto);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("토폴로지 설정 업데이트 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}