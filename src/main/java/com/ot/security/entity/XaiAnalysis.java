package com.ot.security.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "xai_analysis")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class XaiAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // --- FK 설정 (1:1 매핑의 주인) ---
    // name = "threat_id" : DB 컬럼명을 Threat의 PK인 threat_id와 매핑
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "threat_id", referencedColumnName = "threat_id", nullable = false)
    @ToString.Exclude // Lombok 무한 루프 방지
    private Threat threat;

    // --- 중복 필드 제거됨 ---
    // threatType, sourceIp, destinationAssetIp, threatIndex, threatId 제거
    // 필요 시 threat.getSourceIp() 형태로 접근 가능

    @Column(name = "detection_details", columnDefinition = "TEXT")
    private String detectionDetails;

    @Column(columnDefinition = "TEXT")
    private String violation;

    @Column(columnDefinition = "TEXT")
    private String conclusion;

    // 분석이 생성된 시점
    @Column(name = "created_at", updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    // 편의 메서드: 양방향 관계 설정을 쉽게 하기 위함
    public void setThreat(Threat threat) {
        this.threat = threat;
        if (threat != null && threat.getXaiAnalysis() != this) {
            threat.setXaiAnalysis(this);
        }
    }
}