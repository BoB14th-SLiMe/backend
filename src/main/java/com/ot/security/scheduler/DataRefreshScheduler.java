package com.ot.security.scheduler;

import com.ot.security.dto.DashboardStatsDTO;
import com.ot.security.model.ThreatEvent;
import com.ot.security.service.ElasticsearchService;
import com.ot.security.service.SSEService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class DataRefreshScheduler {

    private final ElasticsearchService elasticsearchService;
    private final SSEService sseService;

    private long lastThreatCount = 0;
    private long lastPacketCount = 0;

    /**
     * 5초마다 새로운 데이터 확인 및 SSE 푸시
     */
    @Scheduled(fixedDelayString = "${ot-security.refresh-interval}")
    public void refreshData() {
        try {
            // 최근 위협 확인
            long currentThreatCount = elasticsearchService.getTotalThreats();
            if (currentThreatCount > lastThreatCount) {
                // 새로운 위협 발생
                List<ThreatEvent> recentThreats = elasticsearchService.searchThreats(0, 5);
                if (!recentThreats.isEmpty()) {
                    log.info("새로운 위협 감지: {} 건", recentThreats.size());
                    recentThreats.forEach(threat -> sseService.sendThreat(threat));
                }
                lastThreatCount = currentThreatCount;
            }

            // 최근 패킷 확인
            long currentPacketCount = elasticsearchService.getTotalPackets();
            if (currentPacketCount > lastPacketCount) {
                log.debug("새로운 패킷 감지: {} → {}", lastPacketCount, currentPacketCount);
                lastPacketCount = currentPacketCount;
            }

        } catch (IOException e) {
            log.error("데이터 새로고침 실패", e);
        }
    }

    /**
     * 30초마다 통계 업데이트 및 SSE 푸시
     */
    @Scheduled(fixedRate = 30000)
    public void refreshStats() {
        try {
            long totalPackets = elasticsearchService.getTotalPackets();
            long totalThreats = elasticsearchService.getTotalThreats();
            long recentPackets = elasticsearchService.countRecentPackets(5);
            long recentThreats = elasticsearchService.countRecentThreats(5);

            var threatsByLevel = elasticsearchService.aggregateThreatsByLevel();
            var threatsByType = elasticsearchService.aggregateThreatsByType();

            DashboardStatsDTO stats = DashboardStatsDTO.builder()
                .totalPackets(totalPackets)
                .totalThreats(totalThreats)
                .recentPackets(recentPackets)
                .recentThreats(recentThreats)
                .packetsPerSecond(recentPackets / 300.0)
                .threatsByLevel(threatsByLevel)
                .threatsByType(threatsByType)
                .lastUpdate(Instant.now().toString())
                .build();

            sseService.sendStats(stats);
            log.debug("통계 업데이트 전송: packets={}, threats={}", totalPackets, totalThreats);

        } catch (IOException e) {
            log.error("통계 새로고침 실패", e);
        }
    }

    /**
     * 30초마다 하트비트 전송
     */
    @Scheduled(fixedDelayString = "${ot-security.sse.heartbeat}")
    public void sendHeartbeat() {
        sseService.sendHeartbeat();
        log.debug("하트비트 전송 - 활성 연결: {}", sseService.getActiveConnections());
    }
}
