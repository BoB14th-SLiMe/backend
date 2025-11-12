package com.ot.security.service;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.SortOrder;
import co.elastic.clients.elasticsearch._types.aggregations.StringTermsAggregate;
import co.elastic.clients.elasticsearch._types.aggregations.StringTermsBucket;
import co.elastic.clients.elasticsearch.core.SearchResponse;
import co.elastic.clients.elasticsearch.core.search.Hit;
import com.ot.security.entity.Packet;
import com.ot.security.entity.ThreatEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class ElasticsearchService {

    private final ElasticsearchClient elasticsearchClient;

    @Value("${ot-security.elasticsearch.packet-index}")
    private String packetIndex;

    @Value("${ot-security.elasticsearch.threat-index}")
    private String threatIndex;

    /**
     * 패킷 검색
     */
    public List<Packet> searchPackets(int from, int size) throws IOException {
        SearchResponse<Packet> response = elasticsearchClient.search(s -> s
            .index(packetIndex + "-*")
            .from(from)
            .size(size)
            .sort(sort -> sort.field(f -> f.field("@timestamp").order(SortOrder.Desc))),
            Packet.class
        );

        List<Packet> packets = new ArrayList<>();
        for (Hit<Packet> hit : response.hits().hits()) {
            packets.add(hit.source());
        }
        return packets;
    }

    /**
     * 위협 이벤트 검색
     */
    public List<ThreatEvent> searchThreats(int from, int size) throws IOException {
        SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
            .index(threatIndex + "-*")
            .from(from)
            .size(size)
            .sort(sort -> sort.field(f -> f.field("@timestamp").order(SortOrder.Desc))),
            ThreatEvent.class
        );

        List<ThreatEvent> threats = new ArrayList<>();
        for (Hit<ThreatEvent> hit : response.hits().hits()) {
            threats.add(hit.source());
        }
        return threats;
    }

    /**
     * 최근 N분 패킷 개수
     */
    public long countRecentPackets(int minutes) throws IOException {
        String timestamp = Instant.now().minus(minutes, ChronoUnit.MINUTES).toString();
        
        SearchResponse<Packet> response = elasticsearchClient.search(s -> s
            .index(packetIndex + "-*")
            .size(0)
            .query(q -> q
                .range(r -> r
                    .field("@timestamp")
                    .gte(co.elastic.clients.json.JsonData.of(timestamp))
                )
            ),
            Packet.class
        );

        return response.hits().total().value();
    }

    /**
     * 특정 IP에 대한 최근 N분 위협 개수
     */
    public long countThreatsForIp(String ipAddress, int minutes) throws IOException {
        try {
            String timestamp = Instant.now().minus(minutes, ChronoUnit.MINUTES).toString();

            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                            .index(threatIndex + "-*")
                            .size(0)
                            .query(q -> q.bool(b -> b
                                    .must(m -> m.range(r -> r
                                            .field("@timestamp")
                                            .gte(co.elastic.clients.json.JsonData.of(timestamp))
                                    ))
                                    .should(sh -> sh.term(t -> t
                                            .field("src_ip.keyword")
                                            .value(ipAddress)
                                    ))
                                    .should(sh -> sh.term(t -> t
                                            .field("dst_ip.keyword")
                                            .value(ipAddress)
                                    ))
                                    .minimumShouldMatch("1")
                            )),
                    ThreatEvent.class
            );

            return response.hits().total().value();
        } catch (Exception e) {
            log.warn("IP별 위협 카운트 실패: {}", e.getMessage());
            return 0;
        }
    }

    /**
     * 특정 IP에 대한 최근 N분 패킷 개수
     */
    public long countPacketsForIp(String ipAddress, int minutes) throws IOException {
        try {
            String timestamp = Instant.now().minus(minutes, ChronoUnit.MINUTES).toString();

            SearchResponse<Packet> response = elasticsearchClient.search(s -> s
                            .index(packetIndex + "-*")
                            .size(0)
                            .query(q -> q.bool(b -> b
                                    .must(m -> m.range(r -> r
                                            .field("@timestamp")
                                            .gte(co.elastic.clients.json.JsonData.of(timestamp))
                                    ))
                                    .should(sh -> sh.term(t -> t
                                            .field("src_ip.keyword")
                                            .value(ipAddress)
                                    ))
                                    .should(sh -> sh.term(t -> t
                                            .field("dst_ip.keyword")
                                            .value(ipAddress)
                                    ))
                                    .minimumShouldMatch("1")
                            )),
                    Packet.class
            );

            return response.hits().total().value();
        } catch (Exception e) {
            log.warn("IP별 패킷 카운트 실패: {}", e.getMessage());
            return 0;
        }
    }

    /**
     * 최근 N분 위협 개수
     */
    public long countRecentThreats(int minutes) throws IOException {
        try {
            String timestamp = Instant.now().minus(minutes, ChronoUnit.MINUTES).toString();
            
            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                .index(threatIndex + "-*")
                .size(0)
                .query(q -> q
                    .range(r -> r
                        .field("@timestamp")
                        .gte(co.elastic.clients.json.JsonData.of(timestamp))
                    )
                ),
                ThreatEvent.class
            );

            return response.hits().total().value();
        } catch (Exception e) {
            log.warn("최근 위협 카운트 실패 (인덱스 없음): {}", e.getMessage());
            return 0;
        }
    }

    /**
     * 위협 레벨별 집계
     */
    public Map<String, Long> aggregateThreatsByLevel() throws IOException {
        try {
            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                .index(threatIndex + "-*")
                .size(0)
                .aggregations("by_level", a -> a
                    .terms(t -> t
                        .field("threat_level.keyword")
                        .size(10)
                    )
                ),
                ThreatEvent.class
            );

            Map<String, Long> result = new HashMap<>();
            if (response.aggregations().get("by_level") != null) {
                StringTermsAggregate aggregate = response.aggregations()
                    .get("by_level")
                    .sterms();

                for (StringTermsBucket bucket : aggregate.buckets().array()) {
                    result.put(bucket.key().stringValue(), bucket.docCount());
                }
            }

            return result;
        } catch (Exception e) {
            log.warn("위협 레벨 집계 실패 (인덱스 없음): {}", e.getMessage());
            return new HashMap<>();
        }
    }

    /**
     * 위협 타입별 집계
     */
    public Map<String, Long> aggregateThreatsByType() throws IOException {
        try {
            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                .index(threatIndex + "-*")
                .size(0)
                .aggregations("by_type", a -> a
                    .terms(t -> t
                        .field("threat_type.keyword")
                        .size(10)
                    )
                ),
                ThreatEvent.class
            );

            Map<String, Long> result = new HashMap<>();
            if (response.aggregations().get("by_type") != null) {
                StringTermsAggregate aggregate = response.aggregations()
                    .get("by_type")
                    .sterms();

                for (StringTermsBucket bucket : aggregate.buckets().array()) {
                    result.put(bucket.key().stringValue(), bucket.docCount());
                }
            }

            return result;
        } catch (Exception e) {
            log.warn("위협 타입 집계 실패 (인덱스 없음): {}", e.getMessage());
            return new HashMap<>();
        }
    }

    /**
     * 프로토콜별 집계
     */
    public Map<String, Long> aggregatePacketsByProtocol() throws IOException {
        SearchResponse<Packet> response = elasticsearchClient.search(s -> s
            .index(packetIndex + "-*")
            .size(0)
            .aggregations("by_protocol", a -> a
                .terms(t -> t
                    .field("protocol.keyword")
                    .size(10)
                )
            ),
            Packet.class
        );

        Map<String, Long> result = new HashMap<>();
        StringTermsAggregate aggregate = response.aggregations()
            .get("by_protocol")
            .sterms();

        for (StringTermsBucket bucket : aggregate.buckets().array()) {
            result.put(bucket.key().stringValue(), bucket.docCount());
        }

        return result;
    }

    /**
     * Top 공격 소스 IP
     */
    public Map<String, Long> getTopAttackerIps(int limit) throws IOException {
        try {
            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                .index(threatIndex + "-*")
                .size(0)
                .aggregations("top_attackers", a -> a
                    .terms(t -> t
                        .field("src_ip.keyword")
                        .size(limit)
                    )
                ),
                ThreatEvent.class
            );

            Map<String, Long> result = new HashMap<>();
            StringTermsAggregate aggregate = response.aggregations()
                .get("top_attackers")
                .sterms();

            for (StringTermsBucket bucket : aggregate.buckets().array()) {
                result.put(bucket.key().stringValue(), bucket.docCount());
            }

            return result;
        } catch (Exception e) {
            log.warn("공격자 IP 집계 실패 (인덱스 없음): {}", e.getMessage());
            return new HashMap<>();
        }
    }

    /**
     * Top 공격 대상 IP
     */
    public Map<String, Long> getTopTargetIps(int limit) throws IOException {
        try {
            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                .index(threatIndex + "-*")
                .size(0)
                .aggregations("top_targets", a -> a
                    .terms(t -> t
                        .field("dst_ip.keyword")
                        .size(limit)
                    )
                ),
                ThreatEvent.class
            );

            Map<String, Long> result = new HashMap<>();
            StringTermsAggregate aggregate = response.aggregations()
                .get("top_targets")
                .sterms();

            for (StringTermsBucket bucket : aggregate.buckets().array()) {
                result.put(bucket.key().stringValue(), bucket.docCount());
            }

            return result;
        } catch (Exception e) {
            log.warn("공격 대상 IP 집계 실패 (인덱스 없음): {}", e.getMessage());
            return new HashMap<>();
        }
    }

    /**
     * 전체 패킷 개수
     */
    public long getTotalPackets() throws IOException {
        SearchResponse<Packet> response = elasticsearchClient.search(s -> s
            .index(packetIndex + "-*")
            .size(0),
            Packet.class
        );
        return response.hits().total().value();
    }

    /**
     * 전체 위협 개수
     */
    public long getTotalThreats() throws IOException {
        try {
            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                            .index(threatIndex + "-*")
                            .size(0),
                    ThreatEvent.class
            );
            return response.hits().total().value();
        } catch (Exception e) {
            log.warn("위협 인덱스 조회 실패 (인덱스 없음): {}", e.getMessage());
            return 0;
        }
    }

    /**
     * 시간대별 트래픽 데이터 조회 (24시간)
     * @return 시간대별 트래픽량과 위협 정보를 담은 Map 리스트
     */
    public List<Map<String, Object>> getHourlyTrafficData() throws IOException {
        log.info("=== getHourlyTrafficData() 호출됨 ===");
        try {
            // 24시간 전부터 현재까지
            String timestamp = Instant.now().minus(24, ChronoUnit.HOURS).toString();
            log.info("시간대별 트래픽 조회 시작 - 인덱스: {}-*, 시작시간: {}", packetIndex, timestamp);

            SearchResponse<Packet> response = elasticsearchClient.search(s -> s
                .index(packetIndex + "-*")
                .size(0)
                .query(q -> q
                    .range(r -> r
                        .field("@timestamp")
                        .gte(co.elastic.clients.json.JsonData.of(timestamp))
                    )
                )
                .aggregations("by_hour", a -> a
                    .dateHistogram(dh -> dh
                        .field("@timestamp")
                        .fixedInterval(fi -> fi.time("1h"))
                    )
                ),
                Packet.class
            );

            log.info("Elasticsearch 응답 - total hits: {}", response.hits().total().value());

            List<Map<String, Object>> result = new ArrayList<>();

            if (response.aggregations().get("by_hour") != null) {
                var buckets = response.aggregations()
                    .get("by_hour")
                    .dateHistogram()
                    .buckets()
                    .array();

                log.info("버킷 개수: {}", buckets.size());

                for (var bucket : buckets) {
                    Map<String, Object> data = new HashMap<>();
                    data.put("time", bucket.keyAsString());
                    long packetCount = bucket.docCount();
                    data.put("count", packetCount);

                    // 패킷 개수를 기반으로 트래픽 추정
                    // 평균 패킷 크기를 1500 bytes로 가정 (Ethernet MTU)
                    double avgPacketSize = 1500.0; // bytes
                    double totalBytes = (double) packetCount * avgPacketSize;
                    // bytes를 Mbps로 변환 (1시간 = 3600초)
                    double mbps = (totalBytes * 8.0) / (1024.0 * 1024.0 * 3600.0);
                    double roundedMbps = Math.round(mbps * 100.0) / 100.0;
                    data.put("value", roundedMbps);

                    result.add(data);
                    log.debug("버킷: time={}, count={}, bytes={}, mbps={}", bucket.keyAsString(), packetCount, totalBytes, roundedMbps);
                }
            } else {
                log.warn("집계 데이터 없음!");
            }

            log.info("반환할 결과 개수: {}", result.size());
            return result;
        } catch (Exception e) {
            log.error("시간대별 트래픽 데이터 조회 실패: {}", e.getMessage(), e);
            e.printStackTrace();
            return new ArrayList<>();
        }
    }

    /**
     * 시간대별 위협 데이터 조회 (24시간)
     * @return 시간대별 위협 발생 횟수를 담은 Map 리스트
     */
    public List<Map<String, Object>> getHourlyThreatData() throws IOException {
        log.info("=== getHourlyThreatData() 호출됨 ===");
        try {
            String timestamp = Instant.now().minus(24, ChronoUnit.HOURS).toString();
            log.info("시간대별 위협 조회 시작 - 인덱스: {}-*, 시작시간: {}", threatIndex, timestamp);

            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                .index(threatIndex + "-*")
                .size(0)
                .query(q -> q
                    .range(r -> r
                        .field("@timestamp")
                        .gte(co.elastic.clients.json.JsonData.of(timestamp))
                    )
                )
                .aggregations("by_hour", a -> a
                    .dateHistogram(dh -> dh
                        .field("@timestamp")
                        .fixedInterval(fi -> fi.time("1h"))
                    )
                ),
                ThreatEvent.class
            );

            List<Map<String, Object>> result = new ArrayList<>();

            if (response.aggregations().get("by_hour") != null) {
                var buckets = response.aggregations()
                    .get("by_hour")
                    .dateHistogram()
                    .buckets()
                    .array();

                for (var bucket : buckets) {
                    Map<String, Object> data = new HashMap<>();
                    data.put("time", bucket.keyAsString());
                    data.put("count", bucket.docCount());
                    result.add(data);
                }
            }

            return result;
        } catch (Exception e) {
            log.warn("시간대별 위협 데이터 조회 실패: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * 7일 평균 트래픽 데이터 조회 (시간대별)
     * @return 시간대별 평균 트래픽량을 담은 Map 리스트
     */
    public List<Map<String, Object>> getWeeklyAverageTraffic() throws IOException {
        log.info("=== getWeeklyAverageTraffic() 호출됨 ===");
        try {
            // 7일 전부터 현재까지
            String timestamp = Instant.now().minus(7, ChronoUnit.DAYS).toString();
            log.info("7일 평균 트래픽 조회 시작 - 인덱스: {}-*, 시작시간: {}", packetIndex, timestamp);

            SearchResponse<Packet> response = elasticsearchClient.search(s -> s
                .index(packetIndex + "-*")
                .size(0)
                .query(q -> q
                    .range(r -> r
                        .field("@timestamp")
                        .gte(co.elastic.clients.json.JsonData.of(timestamp))
                    )
                )
                .aggregations("by_hour", a -> a
                    .dateHistogram(dh -> dh
                        .field("@timestamp")
                        .fixedInterval(fi -> fi.time("1h"))
                    )
                ),
                Packet.class
            );

            // 시간대별(0-23시)로 그룹화하여 평균 계산
            Map<Integer, List<Double>> hourlyValues = new HashMap<>();
            for (int i = 0; i < 24; i++) {
                hourlyValues.put(i, new ArrayList<>());
            }

            if (response.aggregations().get("by_hour") != null) {
                var buckets = response.aggregations()
                    .get("by_hour")
                    .dateHistogram()
                    .buckets()
                    .array();

                double avgPacketSize = 1500.0; // bytes

                for (var bucket : buckets) {
                    String timeStr = bucket.keyAsString();
                    Instant instant = Instant.parse(timeStr);
                    int hour = instant.atZone(java.time.ZoneId.systemDefault()).getHour();

                    long packetCount = bucket.docCount();
                    double totalBytes = (double) packetCount * avgPacketSize;
                    double mbps = (totalBytes * 8.0) / (1024.0 * 1024.0 * 3600.0);
                    hourlyValues.get(hour).add(mbps);
                }
            }

            // 평균 계산
            List<Map<String, Object>> result = new ArrayList<>();
            for (int hour = 0; hour < 24; hour++) {
                List<Double> values = hourlyValues.get(hour);
                double average = values.isEmpty() ? 0 :
                    values.stream().mapToDouble(Double::doubleValue).average().orElse(0);

                Map<String, Object> data = new HashMap<>();
                data.put("hour", hour);
                data.put("value", Math.round(average * 100.0) / 100.0);
                result.add(data);
            }

            return result;
        } catch (Exception e) {
            log.error("7일 평균 트래픽 데이터 조회 실패: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

}