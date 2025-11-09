package com.ot.security.service;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.SortOrder;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;
import co.elastic.clients.elasticsearch.core.SearchResponse;
import co.elastic.clients.elasticsearch.core.search.Hit;
import com.ot.security.dto.ThreatFilterDTO;
import com.ot.security.dto.PagedResponseDTO;
import com.ot.security.entity.ThreatEvent;
import com.ot.security.entity.AdminAction;
import com.ot.security.repository.AdminActionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class ThreatFilterService {

    private final ElasticsearchClient elasticsearchClient;
    private final AdminActionRepository adminActionRepository;

    @Value("${ot-security.elasticsearch.threat-index}")
    private String threatIndex;

    /**
     * 위협 필터링
     */
    public PagedResponseDTO<ThreatEvent> filterThreats(ThreatFilterDTO filter) throws Exception {
        // 쿼리 빌더
        List<Query> mustQueries = new ArrayList<>();

        // 날짜 범위
        if (filter.getStartDate() != null || filter.getEndDate() != null) {
            var rangeQuery = Query.of(q -> q.range(r -> {
                var range = r.field("@timestamp");
                if (filter.getStartDate() != null) {
                    range.gte(co.elastic.clients.json.JsonData.of(filter.getStartDate()));
                }
                if (filter.getEndDate() != null) {
                    range.lte(co.elastic.clients.json.JsonData.of(filter.getEndDate()));
                }
                return range;
            }));
            mustQueries.add(rangeQuery);
        }

        // 심각도 필터
        if (filter.getSeverity() != null && !filter.getSeverity().equals("all")) {
            mustQueries.add(Query.of(q -> q.term(t -> t
                    .field("threat_level.keyword")
                    .value(mapSeverityToBackend(filter.getSeverity()))
            )));
        }

        // 검색어 (IP, MAC, 위협유형)
        if (filter.getSearchQuery() != null && !filter.getSearchQuery().isEmpty()) {
            List<Query> shouldQueries = new ArrayList<>();
            shouldQueries.add(Query.of(q -> q.wildcard(w -> w
                    .field("src_ip.keyword")
                    .value("*" + filter.getSearchQuery() + "*")
            )));
            shouldQueries.add(Query.of(q -> q.wildcard(w -> w
                    .field("dst_ip.keyword")
                    .value("*" + filter.getSearchQuery() + "*")
            )));
            shouldQueries.add(Query.of(q -> q.wildcard(w -> w
                    .field("threat_type.keyword")
                    .value("*" + filter.getSearchQuery() + "*")
            )));

            mustQueries.add(Query.of(q -> q.bool(b -> b
                    .should(shouldQueries)
                    .minimumShouldMatch("1")
            )));
        }

        // 검색 실행
        SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                        .index(threatIndex + "-*")
                        .query(q -> q.bool(b -> b.must(mustQueries)))
                        .from(filter.getPage() * filter.getSize())
                        .size(filter.getSize())
                        .sort(sort -> sort.field(f -> f
                                .field("@timestamp")
                                .order(filter.getSort().contains("asc") ? SortOrder.Asc : SortOrder.Desc)
                        )),
                ThreatEvent.class
        );

        List<ThreatEvent> threats = new ArrayList<>();
        for (Hit<ThreatEvent> hit : response.hits().hits()) {
            threats.add(hit.source());
        }

        return PagedResponseDTO.<ThreatEvent>builder()
                .content(threats)
                .totalElements(response.hits().total().value())
                .totalPages((int) Math.ceil(response.hits().total().value() / (double) filter.getSize()))
                .number(filter.getPage())
                .size(filter.getSize())
                .build();
    }

    /**
     * 위협 상세 조회
     */
    public Map<String, Object> getThreatDetail(String threatId) throws Exception {
        SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                        .index(threatIndex + "-*")
                        .query(q -> q.term(t -> t.field("threat_id.keyword").value(threatId)))
                        .size(1),
                ThreatEvent.class
        );

        if (response.hits().hits().isEmpty()) {
            throw new RuntimeException("위협을 찾을 수 없습니다: " + threatId);
        }

        ThreatEvent threat = response.hits().hits().get(0).source();

        // 상세 정보 구성
        Map<String, Object> detail = new HashMap<>();
        detail.put("threatId", threat.getThreatId());
        detail.put("timestamp", threat.getTimestamp());
        detail.put("severity", mapSeverityToFrontend(threat.getThreatLevel()));

        // 분석 내용
        Map<String, Object> analysis = new HashMap<>();
        analysis.put("targetAsset", threat.getDstIp());
        analysis.put("attackVector", threat.getThreatType());
        analysis.put("description", threat.getDescription());
        detail.put("analysis", analysis);

        // 위험 사항
        Map<String, Object> risks = new HashMap<>();
        risks.put("summary", generateRiskSummary(threat));
        risks.put("impactLevel", threat.getThreatLevel());
        detail.put("risks", risks);

        // 결론
        detail.put("conclusion", "추가 모니터링이 권장됩니다.");

        return detail;
    }

    /**
     * 관리자 사후조치 저장
     */
    public void saveAdminAction(String threatId, Map<String, Object> actionData) {
        AdminAction action = adminActionRepository.findByThreatId(threatId)
                .orElse(AdminAction.builder()
                        .threatId(threatId)
                        .build());

        if (actionData.containsKey("status")) {
            action.setStatus((String) actionData.get("status"));
        }
        if (actionData.containsKey("author")) {
            action.setAuthor((String) actionData.get("author"));
        }
        if (actionData.containsKey("content")) {
            action.setContent((String) actionData.get("content"));
        }
        if (actionData.containsKey("completedAt")) {
            try {
                String dateStr = (String) actionData.get("completedAt");
                action.setCompletedAt(Instant.parse(dateStr));
            } catch (Exception e) {
                log.warn("날짜 파싱 실패: {}", actionData.get("completedAt"));
            }
        }

        adminActionRepository.save(action);
        log.info("관리자 사후조치 저장: {} - {}", threatId, action.getStatus());
    }

    /**
     * 위협 타임라인
     */
    public Map<String, Object> getThreatTimeline(String range) throws Exception {
        int minutes = range.equals("7d") ? 10080 : 1440; // 7일 또는 24시간
        String interval = range.equals("7d") ? "1d" : "1h";

        String timestamp = Instant.now().minus(minutes, ChronoUnit.MINUTES).toString();

        SearchResponse<ThreatEvent> response = elasticsearchClient.search(s -> s
                        .index(threatIndex + "-*")
                        .query(q -> q.range(r -> r
                                .field("@timestamp")
                                .gte(co.elastic.clients.json.JsonData.of(timestamp))
                        ))
                        .size(0)
                        .aggregations("timeline", a -> a
                                .dateHistogram(dh -> dh
                                        .field("@timestamp")
                                        .fixedInterval(fi -> fi.time(interval))
                                )
                        ),
                ThreatEvent.class
        );

        // 결과 변환
        var buckets = response.aggregations()
                .get("timeline")
                .dateHistogram()
                .buckets()
                .array();

        List<Map<String, Object>> data = new ArrayList<>();
        for (var bucket : buckets) {
            Map<String, Object> point = new HashMap<>();
            point.put("timestamp", bucket.keyAsString());
            point.put("count", bucket.docCount());
            data.add(point);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("range", range);
        result.put("data", data);
        result.put("total", response.hits().total().value());

        return result;
    }

    /**
     * 위협 통계
     */
    public Map<String, Object> getThreatStatistics() throws Exception {
        // Top 5 위협 유형
        SearchResponse<ThreatEvent> typeResponse = elasticsearchClient.search(s -> s
                        .index(threatIndex + "-*")
                        .size(0)
                        .aggregations("top_types", a -> a
                                .terms(t -> t.field("threat_type.keyword").size(5))
                        ),
                ThreatEvent.class
        );

        List<Map<String, Object>> topTypes = new ArrayList<>();
        long total = typeResponse.hits().total().value();

        var typeBuckets = typeResponse.aggregations()
                .get("top_types")
                .sterms()
                .buckets()
                .array();

        for (var bucket : typeBuckets) {
            Map<String, Object> item = new HashMap<>();
            item.put("type", bucket.key().stringValue());
            item.put("count", bucket.docCount());
            item.put("percentage", Math.round(bucket.docCount() * 100.0 / total * 10) / 10.0);
            topTypes.add(item);
        }

        // 등급별 통계
        SearchResponse<ThreatEvent> severityResponse = elasticsearchClient.search(s -> s
                        .index(threatIndex + "-*")
                        .size(0)
                        .aggregations("by_severity", a -> a
                                .terms(t -> t.field("threat_level.keyword"))
                        ),
                ThreatEvent.class
        );

        Map<String, Long> bySeverity = new HashMap<>();
        var severityBuckets = severityResponse.aggregations()
                .get("by_severity")
                .sterms()
                .buckets()
                .array();

        for (var bucket : severityBuckets) {
            bySeverity.put(
                    mapSeverityToFrontend(bucket.key().stringValue()),
                    bucket.docCount()
            );
        }

        Map<String, Object> result = new HashMap<>();
        result.put("topThreatTypes", topTypes);
        result.put("bySeverity", bySeverity);

        return result;
    }

    // 헬퍼 메서드
    private String mapSeverityToBackend(String frontend) {
        return switch (frontend) {
            case "긴급" -> "critical";
            case "경고" -> "high";
            default -> frontend.toLowerCase();
        };
    }

    private String mapSeverityToFrontend(String backend) {
        return switch (backend) {
            case "critical" -> "긴급";
            case "high" -> "경고";
            default -> backend;
        };
    }

    private String generateRiskSummary(ThreatEvent threat) {
        return String.format(
                "%s 위협이 %s에서 %s로 감지되었습니다.",
                threat.getThreatType(),
                threat.getSrcIp(),
                threat.getDstIp()
        );
    }
}