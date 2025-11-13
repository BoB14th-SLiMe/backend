package com.ot.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.Instant;

@Entity
@Table(name = "xai_analysis")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class XaiAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Instant timestamp;

    @Column(name = "threat_type")
    private String threatType;

    @Column(name = "source_ip")
    private String sourceIp;

    @Column(name = "destination_asset_ip")
    private String destinationAssetIp;

    @Column(name = "threat_index")
    private Integer threatIndex;

    @Column(name = "threat_id", length = 255)
    private String threatId;

    @Column(name = "detection_details", columnDefinition = "TEXT")
    private String detectionDetails;

    @Column(columnDefinition = "TEXT")
    private String violation;

    @Column(columnDefinition = "TEXT")
    private String conclusion;

    @Column(name = "created_at", updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();
}
