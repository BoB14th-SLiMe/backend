package com.ot.security.repository;

import com.ot.security.entity.SystemSettings;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SystemSettingsRepository extends JpaRepository<SystemSettings, Integer> {
    // 항상 ID=1인 단일 레코드만 사용
    default SystemSettings getSettings() {
        return findById(1).orElseGet(() -> {
            SystemSettings settings = SystemSettings.builder()
                    .id(1)
                    .autoRefreshInterval(30)
                    .dataRetentionDays(90)
                    .cpuThreshold(80)
                    .ramThreshold(85)
                    .gpuThreshold(90)
                    .build();
            return save(settings);
        });
    }
}