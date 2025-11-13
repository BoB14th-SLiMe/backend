package com.ot.security.service;

import com.ot.security.dto.AssetDTO;
import com.ot.security.dto.TopologyStatusDTO;
import com.ot.security.entity.Asset;
import com.ot.security.repository.AssetRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AssetManagementService {

    private final AssetRepository assetRepository;
    private final ElasticsearchService elasticsearchService;
    @Value("${ot-security.assets.auto-status-update:false}")
    private boolean autoStatusUpdateEnabled;

    /**
     * 모든 자산 조회
     */
    public List<AssetDTO> getAllAssets() {
        List<Asset> assets = assetRepository.findAll();
        return assets.stream()
                .map(this::toAssetDTO)
                .collect(Collectors.toList());
    }

    /**
     * 자산 타입별 조회
     */
    public List<AssetDTO> getAssetsByType(String assetType) {
        List<Asset> assets = assetRepository.findByAssetType(assetType);
        return assets.stream()
                .map(this::toAssetDTO)
                .collect(Collectors.toList());
    }

    /**
     * 자산 상세 조회
     */
    public AssetDTO getAssetByAssetId(String assetId) {
        Asset asset = assetRepository.findByAssetId(assetId)
                .orElseThrow(() -> new RuntimeException("자산을 찾을 수 없습니다: " + assetId));
        return toAssetDTO(asset);
    }

    /**
     * 자산 생성
     */
    @Transactional
    public AssetDTO createAsset(AssetDTO dto) {
        // 중복 체크
        if (assetRepository.findByAssetId(dto.getAssetId()).isPresent()) {
            throw new RuntimeException("이미 존재하는 자산 ID입니다: " + dto.getAssetId());
        }

        Asset asset = Asset.builder()
                .assetType(dto.getAssetType())
                .assetId(dto.getAssetId())
                .ipAddress(dto.getIpAddress())
                .macAddress(dto.getMacAddress())
                .name(dto.getName())
                .positionX(dto.getPositionX())
                .positionY(dto.getPositionY())
                .isVisible(dto.getIsVisible() != null ? dto.getIsVisible() : true)
                .status(dto.getStatus() != null ? dto.getStatus() : "normal")
                .lastSeen(Instant.now())
                .build();

        Asset saved = assetRepository.save(asset);

        log.info("자산 생성 완료: {}", saved.getAssetId());
        return toAssetDTO(saved);
    }

    /**
     * 자산 업데이트
     */
    @Transactional
    public AssetDTO updateAsset(String assetId, AssetDTO dto) {
        Asset asset = assetRepository.findByAssetId(assetId)
                .orElseThrow(() -> new RuntimeException("자산을 찾을 수 없습니다: " + assetId));

        if (dto.getName() != null) {
            asset.setName(dto.getName());
        }
        if (dto.getIpAddress() != null) {
            asset.setIpAddress(dto.getIpAddress());
        }
        if (dto.getMacAddress() != null) {
            asset.setMacAddress(dto.getMacAddress());
        }
        if (dto.getPositionX() != null) {
            asset.setPositionX(dto.getPositionX());
        }
        if (dto.getPositionY() != null) {
            asset.setPositionY(dto.getPositionY());
        }
        if (dto.getIsVisible() != null) {
            asset.setIsVisible(dto.getIsVisible());
        }
        if (dto.getStatus() != null) {
            asset.setStatus(dto.getStatus());
        }
        if (dto.getLastSeen() != null) {
            asset.setLastSeen(Instant.parse(dto.getLastSeen()));
        }

        Asset updated = assetRepository.save(asset);
        log.info("자산 업데이트 완료: {}", assetId);
        return toAssetDTO(updated);
    }

    /**
     * 자산 삭제
     */
    @Transactional
    public void deleteAsset(String assetId) {
        Asset asset = assetRepository.findByAssetId(assetId)
                .orElseThrow(() -> new RuntimeException("자산을 찾을 수 없습니다: " + assetId));

        assetRepository.delete(asset);

        log.info("자산 삭제 완료: {}", assetId);
    }

    /**
     * 자산 일괄 생성
     */
    @Transactional
    public List<AssetDTO> createAssetsBulk(List<AssetDTO> dtos) {
        List<AssetDTO> created = new ArrayList<>();

        for (AssetDTO dto : dtos) {
            try {
                // assetId가 없으면 IP 주소 기반으로 생성
                if (dto.getAssetId() == null || dto.getAssetId().isEmpty()) {
                    dto.setAssetId(generateAssetId(dto.getIpAddress()));
                }

                // 중복 체크 - 이미 존재하면 스킵
                if (assetRepository.findByAssetId(dto.getAssetId()).isPresent()) {
                    log.debug("이미 존재하는 자산 ID, 스킵: {}", dto.getAssetId());
                    continue;
                }

                Asset asset = Asset.builder()
                        .assetType(dto.getAssetType())
                        .assetId(dto.getAssetId())
                        .ipAddress(dto.getIpAddress())
                        .macAddress(dto.getMacAddress())
                        .name(dto.getName())
                        .positionX(dto.getPositionX())
                        .positionY(dto.getPositionY())
                        .isVisible(dto.getIsVisible() != null ? dto.getIsVisible() : true)
                        .status(dto.getStatus() != null ? dto.getStatus() : "normal")
                        .lastSeen(Instant.now())
                        .build();

                Asset saved = assetRepository.save(asset);

                created.add(toAssetDTO(saved));
            } catch (Exception e) {
                log.error("자산 생성 실패: {}", dto.getIpAddress(), e);
            }
        }

        log.info("자산 일괄 생성 완료: {}개", created.size());
        return created;
    }

    /**
     * Elasticsearch에서 활성 장비 IP 목록 조회
     */
    public List<String> getActiveDeviceIps() throws Exception {
        return elasticsearchService.getActiveDeviceIps();
    }

    /**
     * assetId 생성 헬퍼 메서드
     */
    private String generateAssetId(String ipAddress) {
        return "ASSET-" + ipAddress.replace(".", "-");
    }

    /**
     * 자산 상태 업데이트 (주기적으로 호출)
     */
    @Transactional
    public void updateAssetStatuses() {
        if (!autoStatusUpdateEnabled) {
            log.debug("자동 자산 상태 업데이트 비활성화됨");
            return;
        }
        List<Asset> assets = assetRepository.findAll();
        Instant now = Instant.now();

        for (Asset asset : assets) {
            try {
                String status = determineAssetStatus(asset, now);

                asset.setStatus(status);
                asset.setLastSeen(now);
                assetRepository.save(asset);

            } catch (Exception e) {
                log.error("자산 상태 업데이트 실패: {}", asset.getAssetId(), e);
            }
        }

        log.debug("자산 상태 업데이트 완료: {} 개", assets.size());
    }

    /**
     * 자산 상태 결정 로직
     * - normal: 최근 5분 이내 트래픽 존재 && 위협 없음
     * - warning: 최근 5분 이내 트래픽 없음
     * - critical: 최근 1시간 이내 해당 IP로 위협 탐지됨
     */
    private String determineAssetStatus(Asset asset, Instant now) throws Exception {
        String currentStatus = asset.getStatus() != null ? asset.getStatus() : "normal";
        String ipAddress = asset.getIpAddress();
        if (ipAddress == null || ipAddress.isBlank()) {
            return currentStatus;
        }
        // 1. 최근 1시간 이내 위협 확인
        long recentThreats = elasticsearchService.countThreatsForIp(ipAddress, 60);
        if (recentThreats > 0) {
            return "critical";
        }

        // 2. 최근 5분 이내 트래픽 확인
        long recentPackets = elasticsearchService.countPacketsForIp(ipAddress, 5);
        if (recentPackets > 0) {
            return "normal";
        }

        // 3. 트래픽 없음 - 기존 상태 유지
        return currentStatus;
    }

    // ===== 헬퍼 메서드 =====

    private AssetDTO toAssetDTO(Asset asset) {
        // 자산 상태 조회
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
                .status(asset.getStatus())
                .lastSeen(asset.getLastSeen() != null ? asset.getLastSeen().toString() : null)
                .build();
    }

    public TopologyStatusDTO getTopologyStatusSnapshot() {
        List<Asset> visibleAssets = assetRepository.findAll()
                .stream()
                .filter(asset -> asset.getIsVisible() == null || Boolean.TRUE.equals(asset.getIsVisible()))
                .collect(Collectors.toList());
        List<TopologyStatusDTO.DeviceStatus> controlDevices = new ArrayList<>();
        List<TopologyStatusDTO.DeviceStatus> plcDevices = new ArrayList<>();

        for (Asset asset : visibleAssets) {
            TopologyStatusDTO.DeviceStatus status = TopologyStatusDTO.DeviceStatus.builder()
                    .assetId(asset.getAssetId())
                    .name(asset.getName())
                    .ip(asset.getIpAddress())
                    .status(asset.getStatus())
                    .assetType(asset.getAssetType())
                    .build();

            String type = asset.getAssetType() != null ? asset.getAssetType().toLowerCase(Locale.ROOT) : "";
            if ("plc".equals(type)) {
                plcDevices.add(status);
            } else if ("scada".equals(type) || "hmi".equals(type)) {
                controlDevices.add(status);
            }
        }

        return TopologyStatusDTO.builder()
                .controlDevices(controlDevices)
                .devices(plcDevices)
                .build();
    }
}
