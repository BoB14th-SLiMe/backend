package com.ot.security.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ThreatEvent {
    
    @JsonProperty("@timestamp")
    private String timestamp;
    
    @JsonProperty("threat_id")
    private String threatId;
    
    @JsonProperty("threat_type")
    private String threatType;  // dos_attack, port_scan, malware, brute_force
    
    @JsonProperty("threat_level")
    private String threatLevel;  // critical, warning

    @JsonProperty("detection_engine")
    private String detectionEngine;  // rule, ml, dl

    @JsonProperty("score")
    private Double score;

    @JsonProperty("src_ip")
    private String srcIp;
    
    @JsonProperty("dst_ip")
    private String dstIp;
    
    private String protocol;
    
    @JsonProperty("src_port")
    private Integer srcPort;
    
    @JsonProperty("dst_port")
    private Integer dstPort;
    
    private String description;
    
    @JsonProperty("attack_signature")
    private String attackSignature;
    
    @JsonProperty("packet_count")
    private Integer packetCount;
    
    @JsonProperty("bytes_transferred")
    private Long bytesTransferred;
    
    private Double confidence;  // 0.0 ~ 1.0

    private String status;  // new, investigating, completed, false_positive

    @JsonProperty("source_asset_name")
    private String sourceAssetName;

    @JsonProperty("source_asset_note")
    private String sourceAssetNote;

    @JsonProperty("target_asset_name")
    private String targetAssetName;
}
