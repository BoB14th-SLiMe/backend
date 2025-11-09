package com.ot.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 네트워크 토폴로지 설정 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TopologyConfigDTO {
    private java.util.List<AssetPositionDTO> visibleAssets;
    private java.util.List<AssetDTO> allAssets;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AssetPositionDTO {
        private String assetId;
        private Integer x;
        private Integer y;
    }
}