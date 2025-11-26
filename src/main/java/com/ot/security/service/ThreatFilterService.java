package com.ot.security.service;

import com.ot.security.dto.AdminActionDTO;
import com.ot.security.dto.PagedResponseDTO;
import com.ot.security.dto.ThreatFilterDTO;
import com.ot.security.entity.AdminAction;
import com.ot.security.entity.Threat;
import com.ot.security.entity.ThreatEvent;
import com.ot.security.entity.XaiAnalysis;
import com.ot.security.repository.AdminActionRepository;
import com.ot.security.repository.ThreatRepository;
import com.ot.security.repository.XaiAnalysisRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ThreatFilterService {

    private static final DateTimeFormatter DETAIL_TIMESTAMP_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy.MM.dd HH:mm:ss")
                    .withZone(ZoneId.systemDefault());

    private final ThreatRepository threatRepository;
    private final AdminActionRepository adminActionRepository;
    private final XaiAnalysisRepository xaiAnalysisRepository;
    private final ThreatMapper threatMapper;

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * 위협 필터링
     */
    public PagedResponseDTO<ThreatEvent> filterThreats(ThreatFilterDTO filter) {
        Specification<Threat> specification = buildSpecification(filter);
        Sort sort = parseSort(filter.getSort());
        Pageable pageable = PageRequest.of(
                Math.max(filter.getPage(), 0),
                Math.min(Math.max(filter.getSize(), 1), 100),
                sort
        );

        Page<Threat> page = threatRepository.findAll(specification, pageable);
        List<ThreatEvent> content = page.getContent()
                .stream()
                .map(threatMapper::toThreatEvent)
                .collect(Collectors.toList());

        return PagedResponseDTO.<ThreatEvent>builder()
                .content(content)
                .totalElements(page.getTotalElements())
                .totalPages(page.getTotalPages())
                .number(page.getNumber())
                .size(page.getSize())
                .first(page.isFirst())
                .last(page.isLast())
                .build();
    }

    /**
     * 위협 상세 조회 (Threat + XAI 분석 포함)
     */
    public Map<String, Object> getThreatDetail(String threatId) {
        Threat threat = threatRepository.findById(threatId)
                .orElseThrow(() -> new IllegalArgumentException("위협을 찾을 수 없습니다: " + threatId));

        Map<String, Object> detail = new LinkedHashMap<>();
        detail.put("threatId", threat.getThreatId());
        detail.put("timestamp", formatDetailTimestamp(threat.getEventTimestamp()));
        detail.put("severity", mapSeverityToFrontend(threat.getThreatLevel()));
        detail.put("threatType", Optional.ofNullable(threat.getThreatType()).orElse("미정의"));
        detail.put("status", mapStatusToDisplay(threat.getStatus()));
        detail.put("detectionMethod", threat.getDetectionEngine());
        detail.put("score", Optional.ofNullable(threat.getScore()).orElse(0.0));
        detail.put("sourceIp", threat.getSourceIp());
        detail.put("targetDevice", Optional.ofNullable(threat.getDestinationAsset()).orElse(threat.getDestinationIp()));

        Map<String, Object> sourceAsset = new HashMap<>();
        sourceAsset.put("name", Optional.ofNullable(threat.getSourceAsset()).orElse("-"));
        sourceAsset.put("ip", threat.getSourceIp());
        detail.put("sourceAsset", sourceAsset);

        Map<String, Object> targetAsset = new HashMap<>();
        targetAsset.put("name", Optional.ofNullable(threat.getDestinationAsset()).orElse("-"));
        targetAsset.put("ip", threat.getDestinationIp());
        detail.put("targetAsset", targetAsset);

        Optional<XaiAnalysis> latestAnalysis = findLatestAnalysis(threat);

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("targetAsset", threat.getDestinationAsset());
        analysis.put("attackVector", Optional.ofNullable(threat.getThreatType()).orElse(""));
        analysis.put("description", latestAnalysis
                .map(XaiAnalysis::getDetectionDetails)
                .orElse(generateDefaultAnalysisDescription(threat)));
        detail.put("analysis", analysis);

        latestAnalysis.ifPresent(xai -> {
            Map<String, Object> xaiMap = new HashMap<>();
            xaiMap.put("detection", Optional.ofNullable(xai.getDetectionDetails()).orElse(""));
            xaiMap.put("violation", Optional.ofNullable(xai.getViolation()).orElse(""));
            xaiMap.put("conclusion", Optional.ofNullable(xai.getConclusion()).orElse(""));
            xaiMap.put("timestamp", Optional.ofNullable(xai.getCreatedAt()).map(Instant::toString).orElse(null));
            detail.put("xai_analysis", xaiMap);
        });

        Map<String, Object> risks = new HashMap<>();
        risks.put("summary", latestAnalysis
                .map(XaiAnalysis::getViolation)
                .orElse(generateRiskSummary(threat)));
        risks.put("impactLevel", mapSeverityToFrontend(threat.getThreatLevel()));
        risks.put("score", Optional.ofNullable(threat.getScore()).orElse(0.0));
        detail.put("risks", risks);

        detail.put("conclusion", latestAnalysis
                .map(XaiAnalysis::getConclusion)
                .orElse("추가 모니터링이 권장됩니다."));

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

        String newStatus = null;
        if (actionData.containsKey("status")) {
            newStatus = Objects.toString(actionData.get("status"), action.getStatus());
            action.setStatus(newStatus);
        }
        if (actionData.containsKey("author")) {
            action.setAuthor(Objects.toString(actionData.get("author"), action.getAuthor()));
        }
        if (actionData.containsKey("content")) {
            action.setContent(Objects.toString(actionData.get("content"), action.getContent()));
        }
        if (actionData.containsKey("completedAt")) {
            try {
                String dateStr = Objects.toString(actionData.get("completedAt"), null);
                if (dateStr != null) {
                    action.setCompletedAt(Instant.parse(dateStr));
                }
            } catch (Exception e) {
                log.warn("사후조치 완료 일자 파싱 실패: {}", actionData.get("completedAt"));
            }
        }

        adminActionRepository.save(action);

        // Threat 엔티티의 status도 업데이트
        if (newStatus != null && "completed".equalsIgnoreCase(newStatus)) {
            threatRepository.findById(threatId).ifPresent(threat -> {
                threat.setStatus("조치완료");
                threatRepository.save(threat);
                log.info("위협 상태 업데이트: {} -> 조치완료", threatId);
            });
        }

        log.info("관리자 사후조치 저장: {} - {}", threatId, action.getStatus());
    }

    public AdminActionDTO getAdminAction(String threatId) {
        return adminActionRepository.findByThreatId(threatId)
                .map(this::toAdminActionDTO)
                .orElse(null);
    }

    private AdminActionDTO toAdminActionDTO(AdminAction action) {
        if (action == null) {
            return null;
        }
        return AdminActionDTO.builder()
                .id(action.getId())
                .threatId(action.getThreatId())
                .status(action.getStatus())
                .author(action.getAuthor())
                .content(action.getContent())
                .completedAt(action.getCompletedAt() != null ? action.getCompletedAt().toString() : null)
                .createdAt(action.getCreatedAt() != null ? action.getCreatedAt().toString() : null)
                .updatedAt(action.getUpdatedAt() != null ? action.getUpdatedAt().toString() : null)
                .build();
    }

    /**
     * 위협 타임라인
     */
    public Map<String, Object> getThreatTimeline(String range) {
        boolean weekly = "7d".equalsIgnoreCase(range);
        Instant since = Instant.now().minus(weekly ? 7 : 1, ChronoUnit.DAYS);
        String bucket = weekly ? "day" : "hour";

        String sql = """
                SELECT date_trunc('%s', event_timestamp) AS bucket, COUNT(*) AS cnt
                FROM threats
                WHERE event_timestamp >= :since
                GROUP BY bucket
                ORDER BY bucket
                """.formatted(bucket);

        @SuppressWarnings("unchecked")
        List<Object[]> rows = entityManager.createNativeQuery(sql)
                .setParameter("since", Timestamp.from(since))
                .getResultList();

        List<Map<String, Object>> data = new ArrayList<>();
        long total = 0;
        for (Object[] row : rows) {
            Timestamp ts = (Timestamp) row[0];
            long count = ((Number) row[1]).longValue();
            total += count;

            Map<String, Object> point = new HashMap<>();
            point.put("timestamp", ts.toInstant().toString());
            point.put("count", count);
            data.add(point);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("range", range);
        result.put("data", data);
        result.put("total", total);
        return result;
    }

    /**
     * 위협 통계
     */
    public Map<String, Object> getThreatStatistics() {
        String typeSql = """
                SELECT COALESCE(NULLIF(threat_type, ''), '미지정') AS type, COUNT(*) AS cnt
                FROM threats
                GROUP BY type
                ORDER BY cnt DESC
                LIMIT 5
                """;

        @SuppressWarnings("unchecked")
        List<Object[]> typeRows = entityManager.createNativeQuery(typeSql)
                .getResultList();

        long totalThreats = threatRepository.count();
        List<Map<String, Object>> topTypes = new ArrayList<>();
        for (Object[] row : typeRows) {
            String type = Objects.toString(row[0], "미지정");
            long count = ((Number) row[1]).longValue();
            double percentage = totalThreats > 0
                    ? Math.round((count * 1000.0) / totalThreats) / 10.0
                    : 0.0;

            Map<String, Object> item = new HashMap<>();
            item.put("type", type);
            item.put("count", count);
            item.put("percentage", percentage);
            topTypes.add(item);
        }

        String severitySql = "SELECT threat_level, COUNT(*) AS cnt FROM threats GROUP BY threat_level";
        @SuppressWarnings("unchecked")
        List<Object[]> severityRows = entityManager.createNativeQuery(severitySql)
                .getResultList();

        Map<String, Long> bySeverity = new HashMap<>();
        for (Object[] row : severityRows) {
            String level = Objects.toString(row[0], "warning");
            long count = ((Number) row[1]).longValue();
            bySeverity.put(mapSeverityToFrontend(level), count);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("topThreatTypes", topTypes);
        result.put("bySeverity", bySeverity);
        return result;
    }

    // ===== 내부 유틸 =====

    private Specification<Threat> buildSpecification(ThreatFilterDTO filter) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            String severity = mapSeverityToBackend(filter.getSeverity());
            if (severity != null) {
                predicates.add(cb.equal(root.get("threatLevel"), severity));
            }

            String status = mapStatusToDatabase(filter.getStatus());
            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }

            Instant start = parseInstant(filter.getStartDate());
            if (start != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("eventTimestamp"), start));
            }

            Instant end = parseInstant(filter.getEndDate());
            if (end != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("eventTimestamp"), end));
            }

            if (filter.getSearchQuery() != null && !filter.getSearchQuery().isBlank()) {
                String term = "%" + filter.getSearchQuery().trim().toLowerCase(Locale.ROOT) + "%";
                Predicate srcIp = cb.like(cb.lower(root.get("sourceIp")), term);
                Predicate dstIp = cb.like(cb.lower(root.get("destinationIp")), term);
                Predicate threatType = cb.like(cb.lower(root.get("threatType")), term);
                Predicate sourceAsset = cb.like(cb.lower(root.get("sourceAsset")), term);
                Predicate destinationAsset = cb.like(cb.lower(root.get("destinationAsset")), term);
                predicates.add(cb.or(srcIp, dstIp, threatType, sourceAsset, destinationAsset));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    private Sort parseSort(String sort) {
        if (sort == null || sort.isBlank()) {
            return Sort.by(Sort.Direction.DESC, "eventTimestamp");
        }

        String[] tokens = sort.split(",");
        String property = tokens[0];
        String direction = tokens.length > 1 ? tokens[1] : "desc";

        String mappedProperty = switch (property) {
            case "severity" -> "threatLevel";
            case "detection_engine" -> "detectionEngine";
            case "timestamp" -> "eventTimestamp";
            default -> "eventTimestamp";
        };

        Sort.Direction dir = "asc".equalsIgnoreCase(direction) ? Sort.Direction.ASC : Sort.Direction.DESC;
        return Sort.by(dir, mappedProperty);
    }

    private Instant parseInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (Exception e) {
            log.warn("잘못된 날짜 형식: {}", value);
            return null;
        }
    }

    private String formatDetailTimestamp(Instant timestamp) {
        if (timestamp == null) {
            return "-";
        }
        return DETAIL_TIMESTAMP_FORMATTER.format(timestamp);
    }

    private String mapSeverityToBackend(String frontend) {
        if (frontend == null || frontend.equalsIgnoreCase("all")) {
            return null;
        }
        return switch (frontend.toLowerCase(Locale.ROOT)) {
            case "긴급", "critical", "warning" -> "warning";
            case "경고", "attention" -> "attention";
            default -> null;
        };
    }

    private String mapSeverityToFrontend(String backend) {
        if ("warning".equalsIgnoreCase(backend)) {
            return "긴급";
        }
        return "경고";
    }

    private String mapStatusToDatabase(String status) {
        if (status == null || status.equalsIgnoreCase("all")) {
            return null;
        }
        return switch (status.toLowerCase(Locale.ROOT)) {
            case "pending", "new", "신규" -> "신규";
            case "investigating", "확인중", "확인 중" -> "확인중";
            case "completed", "resolved", "조치완료" -> "조치완료";
            default -> null;
        };
    }

    private String mapStatusToDisplay(String status) {
        if (status == null || status.isBlank()) {
            return "신규";
        }
        return switch (status) {
            case "신규" -> "신규";
            case "확인중", "확인 중" -> "확인중";
            case "조치완료" -> "조치완료";
            default -> status;
        };
    }

    private Optional<XaiAnalysis> findLatestAnalysis(Threat threat) {
        if (threat == null) {
            return Optional.empty();
        }
        if (threat.getThreatIndex() != null) {
            Optional<XaiAnalysis> byIndex = xaiAnalysisRepository
                    .findByThreat_ThreatIndex(threat.getThreatIndex());
            if (byIndex.isPresent()) {
                return byIndex;
            }
        }
        return xaiAnalysisRepository.findByThreat_ThreatId(threat.getThreatId());
    }

    private String generateRiskSummary(Threat threat) {
        String type = Optional.ofNullable(threat.getThreatType()).orElse("비정상 행위");
        String source = Optional.ofNullable(threat.getSourceIp()).orElse("미상");
        String target = Optional.ofNullable(threat.getDestinationIp()).orElse("미상");
        return String.format("%s 위협이 %s에서 %s로 감지되었습니다.", type, source, target);
    }

    private String generateDefaultAnalysisDescription(Threat threat) {
        String engine = Optional.ofNullable(threat.getDetectionEngine()).orElse("RULE");
        String source = Optional.ofNullable(threat.getSourceIp()).orElse("알 수 없음");
        String target = Optional.ofNullable(threat.getDestinationIp()).orElse("알 수 없음");
        return String.format("%s 엔진이 %s → %s 구간에서 이상 트래픽을 탐지했습니다.", engine, source, target);
    }
}
