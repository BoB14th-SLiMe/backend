package com.ot.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SummaryMetricsDTO {
    private Integer safetyScore;
    private Long anomalyDay;
    private Long anomalyWeek;
    private Long newIpCount;
    private Long unconfirmedAlarms;
    private Long criticalAlarms;
    private Boolean autoRefresh;
}
