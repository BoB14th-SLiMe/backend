package com.ot.security.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class XaiAnalysisDTO {

    @JsonProperty("threat_index")
    @JsonAlias("index")
    private Integer threatIndex;
    private String timestamp;

    @JsonProperty("threat_type")
    private String threatType;

    @JsonProperty("source_ip")
    private String sourceIp;

    @JsonProperty("destination_asset_ip")
    private String destinationAssetIp;

    @JsonProperty("detection_engine")
    private String detectionEngine;

    private String status;
    private AnalysisDetailsDTO analysis;

    @Data
    @NoArgsConstructor
    public static class AnalysisDetailsDTO {
        @JsonProperty("detection_details")
        private String detectionDetails;

        private String violation;
        private String conclusion;
    }
}
