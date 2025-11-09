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
            StringTermsAggregate aggregate = response.aggregations()
                .get("by_level")
                .sterms();

            for (StringTermsBucket bucket : aggregate.buckets().array()) {
                result.put(bucket.key().stringValue(), bucket.docCount());
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
            StringTermsAggregate aggregate = response.aggregations()
                .get("by_type")
                .sterms();

            for (StringTermsBucket bucket : aggregate.buckets().array()) {
                result.put(bucket.key().stringValue(), bucket.docCount());
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

}