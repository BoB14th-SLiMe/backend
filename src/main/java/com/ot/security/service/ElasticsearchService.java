package com.ot.security.service;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.SortOrder;
import co.elastic.clients.elasticsearch._types.FieldValue;
import co.elastic.clients.elasticsearch._types.aggregations.CalendarInterval;
import co.elastic.clients.elasticsearch._types.aggregations.CardinalityAggregate;
import co.elastic.clients.elasticsearch._types.aggregations.DateHistogramAggregate;
import co.elastic.clients.elasticsearch._types.aggregations.DateHistogramBucket;
import co.elastic.clients.elasticsearch._types.aggregations.StringTermsAggregate;
import co.elastic.clients.elasticsearch._types.aggregations.StringTermsBucket;
import co.elastic.clients.elasticsearch.core.CountResponse;
import co.elastic.clients.elasticsearch.core.SearchResponse;
import co.elastic.clients.elasticsearch.core.search.Hit;
import co.elastic.clients.json.JsonData;
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

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
     * 최근 N초 패킷 개수
     */
    public long countPacketsSinceSeconds(int seconds) throws IOException {
        if (seconds <= 0) {
            seconds = 1;
        }
        return countPacketsBetweenSeconds(seconds, 0);
    }

    /**
     * 지정한 구간(startSecondsAgo ~ endSecondsAgo) 사이의 패킷 개수를 조회한다.
     * 예: (2, 1)을 넣으면 2초 전부터 1초 전까지 1초 구간의 레코드 수를 반환한다.
     */
    public long countPacketsBetweenSeconds(int startSecondsAgo, int endSecondsAgo) throws IOException {
        if (startSecondsAgo <= endSecondsAgo) {
            throw new IllegalArgumentException("startSecondsAgo 는 endSecondsAgo 보다 커야 합니다.");
        }

        Instant now = Instant.now();
        Instant startInstant = now.minus(startSecondsAgo, ChronoUnit.SECONDS);
        Instant endInstant = now.minus(endSecondsAgo, ChronoUnit.SECONDS);

        CountResponse response = elasticsearchClient.count(c -> c
                .index(packetIndex + "-*")
                .query(q -> q.range(r -> r
                        .field("@timestamp")
                        .gte(JsonData.of(startInstant.toString()))
                        .lt(JsonData.of(endInstant.toString()))
                ))
        );

        return response.count();
    }


    /**
     * 최근 N분 내 특정 레벨의 위협 개수
     */
    public long countThreatsByLevelsSince(List<String> levels, int minutes) throws IOException {
        if (levels == null || levels.isEmpty()) {
            return countRecentThreats(minutes);
        }
        List<FieldValue> levelValues = toFieldValues(levels);
        if (levelValues.isEmpty()) {
            return 0;
        }

        try {
            String timestamp = Instant.now().minus(minutes, ChronoUnit.MINUTES).toString();

            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                    .index(threatIndex + "-*")
                    .size(0)
                    .query(q -> q.bool(b -> b
                            .must(m -> m.range(r -> r
                                    .field("@timestamp")
                                    .gte(JsonData.of(timestamp))
                            ))
                            .must(m -> m.terms(t -> t
                                    .field("threat_level.keyword")
                                    .terms(tt -> tt.value(levelValues))
                            ))
                    )),
                    ThreatEvent.class
            );

            return response.hits().total().value();
        } catch (Exception e) {
            log.warn("레벨별 위협 카운트 실패: {}", e.getMessage());
            return 0;
        }
    }

    /**
     * 최근 N분 내 특정 상태 위협 개수
     */
    public long countThreatsByStatusesSince(List<String> statuses, int minutes) throws IOException {
        if (statuses == null || statuses.isEmpty()) {
            return countRecentThreats(minutes);
        }
        List<FieldValue> statusValues = toFieldValues(statuses);
        if (statusValues.isEmpty()) {
            return 0;
        }

        try {
            String timestamp = Instant.now().minus(minutes, ChronoUnit.MINUTES).toString();

            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                    .index(threatIndex + "-*")
                    .size(0)
                    .query(q -> q.bool(b -> b
                            .must(m -> m.range(r -> r
                                    .field("@timestamp")
                                    .gte(JsonData.of(timestamp))
                            ))
                            .must(m -> m.terms(t -> t
                                    .field("status.keyword")
                                    .terms(tt -> tt.value(statusValues))
                            ))
                    )),
                    ThreatEvent.class
            );

            return response.hits().total().value();
        } catch (Exception e) {
            log.warn("상태별 위협 카운트 실패: {}", e.getMessage());
            return 0;
        }
    }

    /**
     * 최근 N분 내 출발지 IP 기준 유니크 카운트
     */
    public long countUniqueSourceIps(int minutes) throws IOException {
        return getUniqueSourceIps(minutes).size();
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

    /**
     * 7일간 프로토콜 분포 (일별)
     */
    public List<Map<String, Object>> getWeeklyProtocolDistribution() throws IOException {
        try {
            Instant now = Instant.now();
            Instant weekAgo = now.minus(7, ChronoUnit.DAYS);

            // 7일간 일별 프로토콜 집계
            SearchResponse<Packet> response = elasticsearchClient.search(s -> s
                .index(packetIndex + "-*")
                .size(0)
                .query(q -> q
                    .range(r -> r
                        .field("@timestamp")
                        .gte(JsonData.of(weekAgo.toString()))
                        .lt(JsonData.of(now.toString()))
                    )
                )
                .aggregations("by_day", agg -> agg
                    .dateHistogram(dh -> dh
                        .field("@timestamp")
                        .calendarInterval(CalendarInterval.Day)
                    )
                    .aggregations("by_protocol", subAgg -> subAgg
                        .terms(t -> t
                            .field("protocol.keyword")
                            .size(20)
                        )
                    )
                ),
                Packet.class
            );

            List<Map<String, Object>> result = new ArrayList<>();

            if (response.aggregations().get("by_day") != null) {
                DateHistogramAggregate byDay = response.aggregations()
                    .get("by_day")
                    .dateHistogram();

                for (DateHistogramBucket dayBucket : byDay.buckets().array()) {
                    Map<String, Object> dayData = new HashMap<>();
                    dayData.put("date", dayBucket.keyAsString());
                    dayData.put("timestamp", dayBucket.key());

                    Map<String, Long> protocols = new HashMap<>();
                    if (dayBucket.aggregations().get("by_protocol") != null) {
                        StringTermsAggregate byProtocol = dayBucket.aggregations()
                            .get("by_protocol")
                            .sterms();

                        for (StringTermsBucket protocolBucket : byProtocol.buckets().array()) {
                            protocols.put(protocolBucket.key().stringValue(), protocolBucket.docCount());
                        }
                    }

                    dayData.put("protocols", protocols);
                    dayData.put("total", dayBucket.docCount());
                    result.add(dayData);
                }
            }

            return result;
        } catch (Exception e) {
            log.error("7일간 프로토콜 분포 조회 실패: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /**
     * Elasticsearch에서 활성 장비 IP 목록 조회
     * (최근 5분 내 src_ip 또는 dst_ip로 트래픽이 있는 IP)
     */
    public List<String> getActiveDeviceIps() throws IOException {
        try {
            String timestamp = Instant.now().minus(5, ChronoUnit.MINUTES).toString();

            // src_ip aggregation
            SearchResponse<Packet> response = elasticsearchClient.search(s -> s
                .index(packetIndex + "-*")
                .size(0)
                .query(q -> q.range(r -> r
                    .field("@timestamp")
                    .gte(co.elastic.clients.json.JsonData.of(timestamp))
                ))
                .aggregations("src_ips", agg -> agg.terms(t -> t
                    .field("src_ip.keyword")
                    .size(1000)
                ))
                .aggregations("dst_ips", agg -> agg.terms(t -> t
                    .field("dst_ip.keyword")
                    .size(1000)
                )),
                Packet.class
            );

            Set<String> activeIps = new HashSet<>();

            // src_ip 수집
            if (response.aggregations().get("src_ips") != null) {
                StringTermsAggregate srcIps = response.aggregations()
                    .get("src_ips")
                    .sterms();
                for (var bucket : srcIps.buckets().array()) {
                    activeIps.add(bucket.key().stringValue());
                }
            }

            // dst_ip 수집
            if (response.aggregations().get("dst_ips") != null) {
                StringTermsAggregate dstIps = response.aggregations()
                    .get("dst_ips")
                    .sterms();
                for (var bucket : dstIps.buckets().array()) {
                    activeIps.add(bucket.key().stringValue());
                }
            }

            log.debug("활성 장비 IP 개수: {}", activeIps.size());
            return new ArrayList<>(activeIps);
        } catch (Exception e) {
            log.error("활성 장비 IP 조회 실패", e);
            return new ArrayList<>();
        }
    }

    public Set<String> getUniqueSourceIps(int minutes) throws IOException {
        try {
            String timestamp = Instant.now().minus(minutes, ChronoUnit.MINUTES).toString();
            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                            .index(threatIndex + "-*")
                            .size(0)
                            .query(q -> q.range(r -> r
                                    .field("@timestamp")
                                    .gte(JsonData.of(timestamp))
                            ))
                            .aggregations("src_ips", agg -> agg.terms(t -> t
                                    .field("src_ip.keyword")
                                    .size(2000)
                            )),
                    ThreatEvent.class
            );

            Set<String> ips = new HashSet<>();
            if (response.aggregations().get("src_ips") != null) {
                StringTermsAggregate agg = response.aggregations()
                        .get("src_ips")
                        .sterms();
                agg.buckets().array().forEach(bucket -> ips.add(bucket.key().stringValue()));
            }
            return ips;
        } catch (Exception e) {
            log.warn("고유 출발지 IP 조회 실패: {}", e.getMessage());
            return new HashSet<>();
        }
    }

    public List<ThreatEvent> searchRecentThreats(int minutes, int size) throws IOException {
        try {
            String timestamp = Instant.now().minus(minutes, ChronoUnit.MINUTES).toString();

            SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                            .index(threatIndex + "-*")
                            .size(size)
                            .query(q -> q.range(r -> r
                                    .field("@timestamp")
                                    .gte(JsonData.of(timestamp))
                            ))
                            .sort(sort -> sort.field(f -> f
                                    .field("@timestamp")
                                    .order(SortOrder.Desc)
                            )),
                    ThreatEvent.class
            );

            List<ThreatEvent> threats = new ArrayList<>();
            for (Hit<ThreatEvent> hit : response.hits().hits()) {
                threats.add(hit.source());
            }
            return threats;
        } catch (Exception e) {
            log.warn("최근 위협 조회 실패: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    private List<FieldValue> toFieldValues(List<String> values) {
        return values.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(FieldValue::of)
                .collect(Collectors.toList());
    }

}
