package com.ot.security.scheduler;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch.indices.DeleteIndexResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

/**
 * 데이터 보존 정책 스케줄러
 * - 3일보다 오래된 트래픽 데이터를 자동으로 삭제
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataRetentionScheduler {

    private final ElasticsearchClient elasticsearchClient;

    @Value("${ot-security.elasticsearch.packet-index}")
    private String packetIndex;

    @Value("${ot-security.data-retention-days:3}")
    private int retentionDays;

    /**
     * 매일 새벽 2시에 오래된 데이터 삭제
     */
    @Scheduled(cron = "0 0 2 * * ?")
    public void cleanupOldData() {
        log.info("🗑️  데이터 정리 작업 시작 - {}일보다 오래된 데이터 삭제", retentionDays);

        try {
            // 삭제할 날짜 계산 (3일 전)
            Instant cutoffDate = Instant.now().minus(retentionDays, ChronoUnit.DAYS);
            String cutoffDateStr = DateTimeFormatter
                .ofPattern("yyyy.MM.dd")
                .withZone(ZoneId.systemDefault())
                .format(cutoffDate);

            log.info("삭제 기준 날짜: {} ({}일 전)", cutoffDateStr, retentionDays);

            // 오래된 인덱스 삭제
            deleteOldIndices(cutoffDate);

            log.info("✅ 데이터 정리 작업 완료");

        } catch (Exception e) {
            log.error("❌ 데이터 정리 작업 실패", e);
        }
    }

    /**
     * 오래된 인덱스 삭제
     */
    private void deleteOldIndices(Instant cutoffDate) throws Exception {
        DateTimeFormatter formatter = DateTimeFormatter
            .ofPattern("yyyy.MM.dd")
            .withZone(ZoneId.systemDefault());

        // 지난 90일간의 인덱스 확인 (충분한 범위)
        for (int i = retentionDays; i < 90; i++) {
            Instant dateToCheck = Instant.now().minus(i, ChronoUnit.DAYS);
            String indexDate = formatter.format(dateToCheck);
            String indexName = packetIndex + "-" + indexDate;

            try {
                // 인덱스 존재 여부 확인
                boolean exists = elasticsearchClient.indices()
                    .exists(e -> e.index(indexName))
                    .value();

                if (exists) {
                    // 인덱스 삭제
                    DeleteIndexResponse response = elasticsearchClient.indices()
                        .delete(d -> d.index(indexName));

                    if (response.acknowledged()) {
                        log.info("🗑️  삭제됨: {} ({}일 전 데이터)", indexName, i);
                    }
                } else {
                    // 연속으로 3개의 인덱스가 없으면 중단 (더 이상 오래된 인덱스 없음)
                    if (i > retentionDays + 3) {
                        log.debug("더 이상 삭제할 인덱스가 없습니다.");
                        break;
                    }
                }

            } catch (Exception e) {
                log.debug("인덱스 확인 실패: {} - {}", indexName, e.getMessage());
            }
        }
    }

    /**
     * 수동 실행을 위한 메서드 (테스트용)
     */
    public void executeManually() {
        log.info("🔧 수동 데이터 정리 실행");
        cleanupOldData();
    }
}
