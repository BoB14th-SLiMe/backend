package com.ot.security.repository;

import com.ot.security.entity.SummaryMetrics;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SummaryMetricsRepository extends JpaRepository<SummaryMetrics, Long> {
}
