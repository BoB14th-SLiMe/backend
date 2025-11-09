package com.ot.security.repository;

import com.ot.security.entity.BannerMetricConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface BannerMetricConfigRepository extends JpaRepository<BannerMetricConfig, Long> {
    Optional<BannerMetricConfig> findByMetricKey(String metricKey);
    List<BannerMetricConfig> findByIsEnabled(Boolean isEnabled);
    List<BannerMetricConfig> findAllByOrderByDisplayOrderAsc();
}