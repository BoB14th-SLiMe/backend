package com.ot.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.Instant;

@Entity
@Table(name = "admin_actions")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminAction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "threat_id", unique = true, nullable = false, length = 255)
    private String threatId;

    @Column(length = 20)
    private String status = "미작성";  // 미작성, 작성중, 완료

    @Column(length = 100)
    private String author;

    @Column(columnDefinition = "TEXT")
    private String content;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at")
    private Instant updatedAt = Instant.now();

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }
}