package com.ot.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DashboardStatsDTO {
    
    // 전체 통계
    private Long totalPackets;
    private Long totalThreats;
    private Long totalBytes;
    
    // 실시간 통계 (최근 5분)
    private Long recentPackets;
    private Long recentThreats;
    private Double packetsPerSecond;
    
    // 위협 레벨별 카운트
    private Map<String, Long> threatsByLevel;  // critical, high, medium, low
    
    // 위협 타입별 카운트
    private Map<String, Long> threatsByType;   // dos_attack, port_scan, malware
    
    // 프로토콜별 통계
    private Map<String, Long> packetsByProtocol;  // TCP, UDP, ICMP
    
    // Top 공격 소스 IP
    private Map<String, Long> topAttackerIps;
    
    // Top 공격 대상 IP
    private Map<String, Long> topTargetIps;
    
    // 시스템 상태
    private String systemStatus;  // healthy, warning, critical
    private Double cpuUsage;
    private Double memoryUsage;
    
    // 타임스탬프
    private String lastUpdate;
}
