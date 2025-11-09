package com.ot.security.service;

import com.ot.security.dto.AssetDTO;
import com.ot.security.entity.Asset;
import com.ot.security.entity.AssetStatus;
import com.ot.security.repository.AssetRepository;
import com.ot.security.repository.AssetStatusRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AssetManagementService {

    private final AssetRepository assetRepository;
    private final AssetStatusRepository assetStatusRepository;
    private final ElasticsearchService elasticsearchService;

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
                .build();

        Asset saved = assetRepository.save(asset);

        // 자산 상태 초기화
        AssetStatus status = AssetStatus.builder()
                .assetId(saved.getAssetId())
                .status("normal")
                .lastSeen(Instant.now())
                .build();
        assetStatusRepository.save(status);

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

        // 자산 상태도 함께 삭제
        assetStatusRepository.deleteById(assetId);
        assetRepository.delete(asset);

        log.info("자산 삭제 완료: {}", assetId);
    }

    /**
     * 자산 상태 업데이트 (주기적으로 호출)
     */
    @Transactional
    public void updateAssetStatuses() {
        List<Asset> assets = assetRepository.findAll();
        Instant now = Instant.now();

        for (Asset asset : assets) {
            try {
                String status = determineAssetStatus(asset.getIpAddress(), now);

                AssetStatus assetStatus = assetStatusRepository.findById(asset.getAssetId())
                        .orElse(AssetStatus.builder()
                                .assetId(asset.getAssetId())
                                .build());

                assetStatus.setStatus(status);
                assetStatus.setLastSeen(now);

                assetStatusRepository.save(assetStatus);

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
    private String determineAssetStatus(String ipAddress, Instant now) throws Exception {
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

        // 3. 트래픽 없음
        return "warning";
    }

    // ===== 헬퍼 메서드 =====

    private AssetDTO toAssetDTO(Asset asset) {
        // 자산 상태 조회
        String status = assetStatusRepository.findById(asset.getAssetId())
                .map(AssetStatus::getStatus)
                .orElse("unknown");

        String lastSeen = assetStatusRepository.findById(asset.getAssetId())
                .map(s -> s.getLastSeen() != null ? s.getLastSeen().toString() : null)
                .orElse(null);

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
                .status(status)
                .lastSeen(lastSeen)
                .build();
    }
}