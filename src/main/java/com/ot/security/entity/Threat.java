package com.ot.security.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

/**
 * Threat entity persisted in PostgreSQL to provide a canonical record.
 */
@Entity
@Table(name = "threats")
@Getter
@Setter // @Data 대신 @Getter, @Setter 사용 권장 (JPA 관계 시 안전성 위함)
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

    // --- 1:1 양방향 매핑 추가 ---
    // Threat가 삭제되면 분석 데이터도 함께 삭제되도록 Cascade 설정
    @OneToOne(mappedBy = "threat", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @ToString.Exclude // Lombok 무한 루프 방지
    private XaiAnalysis xaiAnalysis;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}