package com.ot.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Packet {
    
    @JsonProperty("@timestamp")
    private String timestamp;
    
    @JsonProperty("src_ip")
    private String srcIp;
    
    @JsonProperty("dst_ip")
    private String dstIp;
    
    private String protocol;
    
    @JsonProperty("src_port")
    private Integer srcPort;
    
    @JsonProperty("dst_port")
    private Integer dstPort;
    
    private Long bytes;
    
    private Integer packets;
    
    private Double duration;
    
    private String flags;
    
    @JsonProperty("threat_level")
    private String threatLevel;  // normal, low, medium, high, critical
    
    @JsonProperty("threat_type")
    private String threatType;   // dos, port_scan, malware, etc.
}
