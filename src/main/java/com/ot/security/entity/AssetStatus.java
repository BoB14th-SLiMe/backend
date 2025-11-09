package com.ot.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.Instant;

@Entity
@Table(name = "asset_status")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AssetStatus {

    @Id
    @Column(name = "asset_id", length = 50)
    private String assetId;

    @Column(length = 20)
    private String status;  // normal, warning, critical

    @Column(name = "last_seen")
    private Instant lastSeen;

    @Column(name = "last_threat_id", length = 255)
    private String lastThreatId;

    @Column(name = "updated_at")
    private Instant updatedAt = Instant.now();

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }
}