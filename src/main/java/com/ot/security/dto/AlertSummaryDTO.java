package com.ot.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlertSummaryDTO {
    private String threatId;
    private String timestamp;
    private String severity;
    private String status;
    private String detectionEngine;
    private String sourceIp;
    private String sourceAsset;
    private String targetIp;
    private String targetAsset;
    private String threatType;
    private Boolean hasXaiAnalysis;  // XAI 분석 존재 여부
}
