package com.ot.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.Instant;

@Entity
@Table(name = "banner_metrics_config")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class BannerMetricConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "metric_key", unique = true, nullable = false, length = 50)
    private String metricKey;

    @Column(length = 100)
    private String label;

    @Column(name = "is_enabled")
    private Boolean isEnabled = true;

    @Column(name = "display_order")
    private Integer displayOrder;

    @Column(name = "updated_at")
    private Instant updatedAt = Instant.now();

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }
}