package com.ot.security.repository;

import com.ot.security.entity.XaiAnalysis;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface XaiAnalysisRepository extends JpaRepository<XaiAnalysis, Long> {
    // 최신순 조회
    Page<XaiAnalysis> findAllByOrderByCreatedAtDesc(Pageable pageable);

    // 특정 기간 내 조회
    List<XaiAnalysis> findByCreatedAtBetweenOrderByCreatedAtDesc(Instant start, Instant end);

    // 최근 N건 조회
    List<XaiAnalysis> findTop10ByOrderByCreatedAtDesc();

    // 특정 시점 이후의 데이터 개수 조회 (배너 통계용)
    long countByCreatedAtAfter(Instant timestamp);

    // Threat 관계를 통한 조회
    Optional<XaiAnalysis> findByThreat_ThreatIndex(Integer threatIndex);

    Optional<XaiAnalysis> findByThreat_ThreatId(String threatId);
}
