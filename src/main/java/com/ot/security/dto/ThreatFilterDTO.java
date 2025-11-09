package com.ot.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 위협 필터링 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatFilterDTO {
    private String severity;      // critical, high, medium, low, all
    private String status;         // unconfirmed, confirmed, resolved, all
    private String startDate;      // ISO 8601 format
    private String endDate;        // ISO 8601 format
    private String searchQuery;    // IP, MAC, 위협유형 검색
    
    @Builder.Default
    private int page = 0;
    
    @Builder.Default
    private int size = 20;
    
    @Builder.Default
    private String sort = "timestamp,desc";
}