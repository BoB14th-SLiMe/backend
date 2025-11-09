package com.ot.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BannerConfigDTO {
    private java.util.List<MetricConfigDTO> enabled;
    private java.util.List<MetricConfigDTO> disabled;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MetricConfigDTO {
        private String key;
        private String label;
        private Integer order;
    }
}
