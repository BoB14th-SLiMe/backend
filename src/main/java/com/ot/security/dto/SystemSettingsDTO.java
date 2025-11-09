package com.ot.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 시스템 설정 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SystemSettingsDTO {
    private Integer autoRefreshInterval;  // 초
    private Integer dataRetentionDays;    // 일
    
    private ThresholdDTO thresholds;
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ThresholdDTO {
        private Integer cpu;
        private Integer ram;
        private Integer gpu;
    }
}
