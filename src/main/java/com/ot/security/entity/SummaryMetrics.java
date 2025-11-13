package com.ot.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "summary_metrics")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SummaryMetrics {

    @Id
    @Column(name = "id")
    @Builder.Default
    private Long id = 1L;

    @Column(name = "safety_score")
    @Builder.Default
    private Integer safetyScore = 0;

    @Column(name = "anomaly_day")
    @Builder.Default
    private Long anomalyDay = 0L;

    @Column(name = "anomaly_week")
    @Builder.Default
    private Long anomalyWeek = 0L;

    @Column(name = "new_ip_count")
    @Builder.Default
    private Long newIpCount = 0L;

    @Column(name = "unconfirmed_alarms")
    @Builder.Default
    private Long unconfirmedAlarms = 0L;

    @Column(name = "critical_alarms")
    @Builder.Default
    private Long criticalAlarms = 0L;

    @Column(name = "auto_refresh")
    @Builder.Default
    private Boolean autoRefresh = false;

    @Column(name = "updated_at")
    private Instant updatedAt;
}
