package com.ot.security.dto;

import lombok.Data;

@Data
public class RiskAlarmDTO {
    private RiskPayload risk;

    @Data
    public static class RiskPayload {
        private Double score;
        private String detected_time;
        private String src_ip;
        private String src_asset;
        private String dst_ip;
        private String dst_asset;
    }
}
