package com.ot.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.Instant;

@Entity
@Table(name = "system_settings")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SystemSettings {

    @Id
    private Integer id = 1;  // 항상 단일 레코드

    @Column(name = "auto_refresh_interval")
    private Integer autoRefreshInterval = 30;

    @Column(name = "data_retention_days")
    private Integer dataRetentionDays = 90;

    @Column(name = "cpu_threshold")
    private Integer cpuThreshold = 80;

    @Column(name = "ram_threshold")
    private Integer ramThreshold = 85;

    @Column(name = "gpu_threshold")
    private Integer gpuThreshold = 90;

    @Column(name = "updated_at")
    private Instant updatedAt = Instant.now();

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }
}