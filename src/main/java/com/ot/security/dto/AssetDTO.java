package com.ot.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 자산 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AssetDTO {
    private Long id;
    private String assetType;    // scada, switch, plc, hmi
    private String assetId;
    private String ipAddress;
    private String macAddress;
    private String name;
    private Integer positionX;
    private Integer positionY;
    private Boolean isVisible;
    private String status;       // normal, warning, critical
    private String lastSeen;
}
