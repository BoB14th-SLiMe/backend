package com.ot.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "system_metrics")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SystemMetrics {

    @Id
    @Builder.Default
    private Integer id = 1; // 항상 단일 레코드

    @Column(name = "timestamp", nullable = false)
    private Instant timestamp;

    @Column(name = "cpu_usage")
    @Builder.Default
    private Double cpuUsage = 50.0; // 초기값

    @Column(name = "ram_usage")
    @Builder.Default
    private Double ramUsage = 50.0; // 초기값

    @Column(name = "gpu_usage")
    @Builder.Default
    private Double gpuUsage = 50.0; // 초기값

    @Column(name = "source")
    @Builder.Default
    private String source = "AI-PC"; // AI PC 식별자

    @PrePersist
    @PreUpdate
    public void prePersist() {
        this.id = 1; // 항상 ID를 1로 고정
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }
}
