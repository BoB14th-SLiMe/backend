package com.ot.security.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Threat entity persisted in PostgreSQL to provide a canonical record
 * that other domain objects (admin actions, XAI 분석 등) can reference.
 */
@Entity
@Table(name = "threats")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Threat {

    @Id
    @Column(name = "threat_id", length = 255)
    private String threatId;

    @Column(name = "threat_index", unique = true, nullable = false)
    private Integer threatIndex;

    @Column(name = "event_timestamp", nullable = false)
    private Instant eventTimestamp;

    @Column(name = "detection_engine", length = 20, nullable = false)
    private String detectionEngine;

    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    @Column(name = "source_asset", length = 100)
    private String sourceAsset;

    @Column(name = "destination_ip", length = 45)
    private String destinationIp;

    @Column(name = "destination_asset", length = 100)
    private String destinationAsset;

    @Builder.Default
    @Column(name = "threat_type", length = 255)
    private String threatType = "";

    @Builder.Default
    @Column(name = "threat_level", length = 20)
    private String threatLevel = "attention";

    @Builder.Default
    @Column(name = "status", length = 20)
    private String status = "신규";

    @Builder.Default
    @Column(name = "score")
    private Double score = 0.0;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}
