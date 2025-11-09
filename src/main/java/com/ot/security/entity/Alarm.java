package com.ot.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.Instant;

@Entity
@Table(name = "alarms")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Alarm {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "threat_id", unique = true, nullable = false, length = 255)
    private String threatId;

    @Column(length = 20)
    private String severity;  // critical, high, medium, low

    @Column(length = 20)
    private String status = "unconfirmed";  // unconfirmed, confirmed, resolved

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "confirmed_at")
    private Instant confirmedAt;

    @Column(name = "resolved_at")
    private Instant resolvedAt;
}