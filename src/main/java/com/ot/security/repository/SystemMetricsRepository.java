package com.ot.security.repository;

import com.ot.security.entity.SystemMetrics;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface SystemMetricsRepository extends JpaRepository<SystemMetrics, Integer> {

    // 최신 메트릭 조회
    Optional<SystemMetrics> findTopByOrderByTimestampDesc();

    // 특정 기간 내 메트릭 조회
    List<SystemMetrics> findByTimestampBetweenOrderByTimestampAsc(Instant start, Instant end);

    // 평균값 계산
    @Query("SELECT AVG(s.cpuUsage) FROM SystemMetrics s WHERE s.timestamp >= :since")
    Double getAverageCpuUsage(Instant since);

    @Query("SELECT AVG(s.ramUsage) FROM SystemMetrics s WHERE s.timestamp >= :since")
    Double getAverageRamUsage(Instant since);

    @Query("SELECT AVG(s.gpuUsage) FROM SystemMetrics s WHERE s.timestamp >= :since")
    Double getAverageGpuUsage(Instant since);
}
