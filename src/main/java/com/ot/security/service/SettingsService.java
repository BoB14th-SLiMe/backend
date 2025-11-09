package com.ot.security.service;

import com.ot.security.dto.*;
import com.ot.security.entity.BannerMetricConfig;
import com.ot.security.entity.SystemSettings;
import com.ot.security.entity.Asset;
import com.ot.security.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class SettingsService {

    private final SystemSettingsRepository systemSettingsRepository;
    private final BannerMetricConfigRepository bannerMetricConfigRepository;
    private final AssetRepository assetRepository;

    /**
     * 시스템 설정 조회
     */
    public SystemSettingsDTO getSystemSettings() {
        SystemSettings settings = systemSettingsRepository.getSettings();

        return SystemSettingsDTO.builder()
                .autoRefreshInterval(settings.getAutoRefreshInterval())
                .dataRetentionDays(settings.getDataRetentionDays())
                .thresholds(SystemSettingsDTO.ThresholdDTO.builder()
                        .cpu(settings.getCpuThreshold())
                        .ram(settings.getRamThreshold())
                        .gpu(settings.getGpuThreshold())
                        .build())
                .build();
    }

    /**
     * 시스템 설정 업데이트
     */
    @Transactional
    public SystemSettingsDTO updateSystemSettings(SystemSettingsDTO dto) {
        SystemSettings settings = systemSettingsRepository.getSettings();

        if (dto.getAutoRefreshInterval() != null) {
            settings.setAutoRefreshInterval(dto.getAutoRefreshInterval());
        }
        if (dto.getDataRetentionDays() != null) {
            settings.setDataRetentionDays(dto.getDataRetentionDays());
        }
        if (dto.getThresholds() != null) {
            if (dto.getThresholds().getCpu() != null) {
                settings.setCpuThreshold(dto.getThresholds().getCpu());
            }
            if (dto.getThresholds().getRam() != null) {
                settings.setRamThreshold(dto.getThresholds().getRam());
            }
            if (dto.getThresholds().getGpu() != null) {
                settings.setGpuThreshold(dto.getThresholds().getGpu());
            }
        }

        SystemSettings saved = systemSettingsRepository.save(settings);
        log.info("시스템 설정 업데이트 완료: {}", saved);

        return getSystemSettings();
    }

    /**
     * 배너 설정 조회
     */
    public BannerConfigDTO getBannerConfig() {
        List<BannerMetricConfig> allConfigs = bannerMetricConfigRepository.findAllByOrderByDisplayOrderAsc();

        // 초기 데이터가 없으면 기본값 생성
        if (allConfigs.isEmpty()) {
            initializeDefaultBannerConfig();
            allConfigs = bannerMetricConfigRepository.findAllByOrderByDisplayOrderAsc();
        }

        List<BannerConfigDTO.MetricConfigDTO> enabled = allConfigs.stream()
                .filter(BannerMetricConfig::getIsEnabled)
                .map(this::toMetricConfigDTO)
                .collect(Collectors.toList());

        List<BannerConfigDTO.MetricConfigDTO> disabled = allConfigs.stream()
                .filter(config -> !config.getIsEnabled())
                .map(this::toMetricConfigDTO)
                .collect(Collectors.toList());

        return BannerConfigDTO.builder()
                .enabled(enabled)
                .disabled(disabled)
                .build();
    }

    /**
     * 배너 설정 업데이트
     */
    @Transactional
    public void updateBannerConfig(BannerConfigDTO dto) {
        // 활성화된 항목 업데이트
        if (dto.getEnabled() != null) {
            for (int i = 0; i < dto.getEnabled().size(); i++) {
                BannerConfigDTO.MetricConfigDTO metricDTO = dto.getEnabled().get(i);
                BannerMetricConfig config = bannerMetricConfigRepository
                        .findByMetricKey(metricDTO.getKey())
                        .orElseThrow(() -> new RuntimeException("메트릭을 찾을 수 없습니다: " + metricDTO.getKey()));

                config.setIsEnabled(true);
                config.setDisplayOrder(metricDTO.getOrder() != null ? metricDTO.getOrder() : i);
                if (metricDTO.getLabel() != null) {
                    config.setLabel(metricDTO.getLabel());
                }

                bannerMetricConfigRepository.save(config);
            }
        }

        // 비활성화된 항목 업데이트
        if (dto.getDisabled() != null) {
            for (BannerConfigDTO.MetricConfigDTO metricDTO : dto.getDisabled()) {
                BannerMetricConfig config = bannerMetricConfigRepository
                        .findByMetricKey(metricDTO.getKey())
                        .orElseThrow(() -> new RuntimeException("메트릭을 찾을 수 없습니다: " + metricDTO.getKey()));

                config.setIsEnabled(false);
                if (metricDTO.getLabel() != null) {
                    config.setLabel(metricDTO.getLabel());
                }

                bannerMetricConfigRepository.save(config);
            }
        }

        log.info("배너 설정 업데이트 완료");
    }

    /**
     * 토폴로지 설정 조회
     */
    public TopologyConfigDTO getTopologyConfig() {
        List<Asset> visibleAssets = assetRepository.findByIsVisible(true);
        List<Asset> allAssets = assetRepository.findAll();

        List<TopologyConfigDTO.AssetPositionDTO> visiblePositions = visibleAssets.stream()
                .map(asset -> TopologyConfigDTO.AssetPositionDTO.builder()
                        .assetId(asset.getAssetId())
                        .x(asset.getPositionX())
                        .y(asset.getPositionY())
                        .build())
                .collect(Collectors.toList());

        List<AssetDTO> allAssetDTOs = allAssets.stream()
                .map(this::toAssetDTO)
                .collect(Collectors.toList());

        return TopologyConfigDTO.builder()
                .visibleAssets(visiblePositions)
                .allAssets(allAssetDTOs)
                .build();
    }

    /**
     * 토폴로지 설정 업데이트
     */
    @Transactional
    public void updateTopologyConfig(TopologyConfigDTO dto) {
        if (dto.getVisibleAssets() != null) {
            for (TopologyConfigDTO.AssetPositionDTO posDTO : dto.getVisibleAssets()) {
                Asset asset = assetRepository.findByAssetId(posDTO.getAssetId())
                        .orElseThrow(() -> new RuntimeException("자산을 찾을 수 없습니다: " + posDTO.getAssetId()));

                asset.setIsVisible(true);
                if (posDTO.getX() != null) {
                    asset.setPositionX(posDTO.getX());
                }
                if (posDTO.getY() != null) {
                    asset.setPositionY(posDTO.getY());
                }

                assetRepository.save(asset);
            }
        }

        log.info("토폴로지 설정 업데이트 완료");
    }

    // ===== 헬퍼 메서드 =====

    private void initializeDefaultBannerConfig() {
        String[] defaultMetrics = {
                "threat_score:위협 점수",
                "anomaly_day:이상탐지(Day)",
                "anomaly_week:이상탐지(Week)",
                "new_ip:새롭게 탐지된 IP",
                "unconfirmed_terminal:미확인 알람",
                "critical_alert:긴급 알람",
                "cpu:CPU 사용량",
                "ram:RAM 사용량",
                "gpu:GPU 사용량"
        };

        for (int i = 0; i < defaultMetrics.length; i++) {
            String[] parts = defaultMetrics[i].split(":");
            BannerMetricConfig config = BannerMetricConfig.builder()
                    .metricKey(parts[0])
                    .label(parts[1])
                    .isEnabled(true)
                    .displayOrder(i)
                    .build();
            bannerMetricConfigRepository.save(config);
        }

        log.info("기본 배너 설정 초기화 완료");
    }

    private BannerConfigDTO.MetricConfigDTO toMetricConfigDTO(BannerMetricConfig config) {
        return BannerConfigDTO.MetricConfigDTO.builder()
                .key(config.getMetricKey())
                .label(config.getLabel())
                .order(config.getDisplayOrder())
                .build();
    }

    private AssetDTO toAssetDTO(Asset asset) {
        return AssetDTO.builder()
                .id(asset.getId())
                .assetType(asset.getAssetType())
                .assetId(asset.getAssetId())
                .ipAddress(asset.getIpAddress())
                .macAddress(asset.getMacAddress())
                .name(asset.getName())
                .positionX(asset.getPositionX())
                .positionY(asset.getPositionY())
                .isVisible(asset.getIsVisible())
                .build();
    }
}