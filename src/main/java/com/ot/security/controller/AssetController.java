package com.ot.security.controller;

import com.ot.security.dto.AssetDTO;
import com.ot.security.service.AssetManagementService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/assets")
@RequiredArgsConstructor
@Tag(name = "Assets", description = "자산 관리 API")
public class AssetController {

    private final AssetManagementService assetManagementService;

    /**
     * 모든 자산 조회
     */
    @GetMapping
    @Operation(summary = "자산 목록 조회", description = "모든 자산을 조회합니다.")
    public ResponseEntity<List<AssetDTO>> getAllAssets() {
        try {
            List<AssetDTO> assets = assetManagementService.getAllAssets();
            return ResponseEntity.ok(assets);
        } catch (Exception e) {
            log.error("자산 목록 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 자산 타입별 조회
     */
    @GetMapping("/type/{assetType}")
    @Operation(summary = "자산 타입별 조회", description = "특정 타입의 자산들을 조회합니다 (scada, switch, plc, hmi).")
    public ResponseEntity<List<AssetDTO>> getAssetsByType(@PathVariable String assetType) {
        try {
            List<AssetDTO> assets = assetManagementService.getAssetsByType(assetType);
            return ResponseEntity.ok(assets);
        } catch (Exception e) {
            log.error("자산 타입별 조회 실패: {}", assetType, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 자산 상세 조회
     */
    @GetMapping("/{assetId}")
    @Operation(summary = "자산 상세 조회", description = "특정 자산의 상세 정보를 조회합니다.")
    public ResponseEntity<AssetDTO> getAsset(@PathVariable String assetId) {
        try {
            AssetDTO asset = assetManagementService.getAssetByAssetId(assetId);
            return ResponseEntity.ok(asset);
        } catch (RuntimeException e) {
            log.error("자산 조회 실패: {}", assetId, e);
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("자산 조회 실패: {}", assetId, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 자산 생성
     */
    @PostMapping
    @Operation(summary = "자산 생성", description = "새로운 자산을 생성합니다.")
    public ResponseEntity<AssetDTO> createAsset(@RequestBody AssetDTO dto) {
        try {
            AssetDTO created = assetManagementService.createAsset(dto);
            return ResponseEntity.ok(created);
        } catch (RuntimeException e) {
            log.error("자산 생성 실패", e);
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            log.error("자산 생성 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 자산 업데이트
     */
    @PutMapping("/{assetId}")
    @Operation(summary = "자산 업데이트", description = "자산 정보를 업데이트합니다.")
    public ResponseEntity<AssetDTO> updateAsset(
            @PathVariable String assetId,
            @RequestBody AssetDTO dto
    ) {
        try {
            AssetDTO updated = assetManagementService.updateAsset(assetId, dto);
            return ResponseEntity.ok(updated);
        } catch (RuntimeException e) {
            log.error("자산 업데이트 실패: {}", assetId, e);
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("자산 업데이트 실패: {}", assetId, e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * 자산 삭제
     */
    @DeleteMapping("/{assetId}")
    @Operation(summary = "자산 삭제", description = "자산을 삭제합니다.")
    public ResponseEntity<Void> deleteAsset(@PathVariable String assetId) {
        try {
            assetManagementService.deleteAsset(assetId);
            return ResponseEntity.ok().build();
        } catch (RuntimeException e) {
            log.error("자산 삭제 실패: {}", assetId, e);
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("자산 삭제 실패: {}", assetId, e);
            return ResponseEntity.internalServerError().build();
        }
    }
}