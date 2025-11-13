package com.ot.security.service;

import com.ot.security.dto.SystemMetricsDTO;
import com.ot.security.entity.SystemMetrics;
import com.ot.security.repository.SystemMetricsRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Random;

@Slf4j
@Service
@RequiredArgsConstructor
public class SystemMetricsService {

    private final SystemMetricsRepository systemMetricsRepository;
    private final Random random = new Random();

    @Transactional
    public void saveMetrics(SystemMetricsDTO dto) {
        // ID=1인 레코드를 찾아서 업데이트, 없으면 생성
        SystemMetrics metrics = systemMetricsRepository.findById(1)
                .orElse(SystemMetrics.builder()
                        .id(1)
                        .cpuUsage(50.0)
                        .ramUsage(50.0)
                        .gpuUsage(50.0)
                        .source("AI-PC")
                        .build());

        // 값 업데이트
        metrics.setCpuUsage(dto.getCpuUsage());
        metrics.setRamUsage(dto.getRamUsage());
        metrics.setGpuUsage(dto.getGpuUsage());
        if (dto.getSource() != null) {
            metrics.setSource(dto.getSource());
        }
        metrics.setTimestamp(Instant.now());

        systemMetricsRepository.save(metrics);
        log.info("시스템 메트릭 업데이트: CPU={}%, RAM={}%, GPU={}%", dto.getCpuUsage(), dto.getRamUsage(), dto.getGpuUsage());
    }

    public SystemMetricsDTO getLatestMetrics() {
        return systemMetricsRepository.findById(1)
                .map(this::toDTO)
                .orElse(SystemMetricsDTO.builder()
                        .cpuUsage(50.0)
                        .ramUsage(50.0)
                        .gpuUsage(50.0)
                        .source("AI-PC")
                        .build());
    }

    public SystemMetricsDTO getAverageMetrics(int minutes) {
        // 단일 레코드 모드에서는 최신 값을 반환
        return getLatestMetrics();
    }

    // 더미 데이터 생성 (프로토타입용) - 초기 데이터 설정
    @Transactional
    public void generateDummyMetrics() {
        SystemMetrics metrics = systemMetricsRepository.findById(1)
                .orElse(SystemMetrics.builder()
                        .id(1)
                        .cpuUsage(50.0)
                        .ramUsage(50.0)
                        .gpuUsage(50.0)
                        .source("AI-PC")
                        .build());

        metrics.setTimestamp(Instant.now());
        systemMetricsRepository.save(metrics);
        log.info("초기 시스템 메트릭 생성: CPU=50%, RAM=50%, GPU=50%");
    }

    private SystemMetricsDTO toDTO(SystemMetrics entity) {
        return SystemMetricsDTO.builder()
                .cpuUsage(entity.getCpuUsage())
                .ramUsage(entity.getRamUsage())
                .gpuUsage(entity.getGpuUsage())
                .source(entity.getSource())
                .build();
    }
}
