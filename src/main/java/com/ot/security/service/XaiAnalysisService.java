package com.ot.security.service;

import com.ot.security.dto.XaiAnalysisDTO;
import com.ot.security.entity.Threat;
import com.ot.security.entity.XaiAnalysis;
import com.ot.security.repository.ThreatRepository;
import com.ot.security.repository.XaiAnalysisRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class XaiAnalysisService {

    private final XaiAnalysisRepository xaiAnalysisRepository;
    private final ThreatRepository threatRepository;
    private final SSEService sseService;
    private final Random random = new Random();

    @Transactional
    public void saveXaiAnalyses(List<XaiAnalysisDTO> analysisList) {
        if (analysisList == null || analysisList.isEmpty()) {
            log.info("수신된 XAI 분석 결과가 없습니다.");
            return;
        }

        List<XaiAnalysis> entities = analysisList.stream()
                .map(this::mapDtoToEntity)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        if (entities.isEmpty()) {
            log.warn("유효한 XAI 분석 데이터가 없어 저장을 건너뜁니다.");
            return;
        }

        List<XaiAnalysis> saved = xaiAnalysisRepository.saveAll(entities);
        log.info("{} 건의 XAI 분석 결과를 저장했습니다.", saved.size());
        notifyRealtimeUpdates(saved);
    }

    private XaiAnalysis mapDtoToEntity(XaiAnalysisDTO dto) {
        Instant timestamp = parseTimestamp(dto.getTimestamp());
        if (timestamp == null) {
            log.warn("타임스탬프가 없어 XAI 결과를 건너뜁니다: {}", dto);
            return null;
        }

        Optional<Threat> threatOpt = resolveThreat(dto, timestamp);
        threatOpt.ifPresent(threat -> synchronizeThreatType(threat, dto));
        String threatId = threatOpt.map(Threat::getThreatId).orElse(null);
        Integer threatIndex = threatOpt.map(Threat::getThreatIndex).orElse(dto.getThreatIndex());

        return XaiAnalysis.builder()
                .timestamp(timestamp)
                .threatType(dto.getThreatType())
                .sourceIp(dto.getSourceIp())
                .destinationAssetIp(dto.getDestinationAssetIp())
                .threatId(threatId)
                .threatIndex(threatIndex)
                .detectionDetails(dto.getAnalysis() != null ? dto.getAnalysis().getDetectionDetails() : null)
                .violation(dto.getAnalysis() != null ? dto.getAnalysis().getViolation() : null)
                .conclusion(dto.getAnalysis() != null ? dto.getAnalysis().getConclusion() : null)
                .build();
    }

    // 페이징 조회
    public Page<XaiAnalysis> getAllAnalyses(Pageable pageable) {
        return xaiAnalysisRepository.findAllByOrderByTimestampDesc(pageable);
    }

    // 최근 10건 조회
    public List<XaiAnalysis> getRecentAnalyses() {
        return xaiAnalysisRepository.findTop10ByOrderByTimestampDesc();
    }

    // 최근 N분 내 분석 개수 조회 (배너 통계용)
    public long countRecentAnalyses(int minutes) {
        Instant since = Instant.now().minus(minutes, ChronoUnit.MINUTES);
        return xaiAnalysisRepository.countByTimestampAfter(since);
    }

    // 더미 데이터 생성 (프로토타입용)
    @Transactional
    public void generateDummyData(int count) {
        List<Threat> threats = threatRepository.findAll();
        if (threats.isEmpty()) {
            log.warn("생성할 위협 데이터가 없어 XAI 더미 데이터를 만들 수 없습니다.");
            return;
        }

        List<XaiAnalysis> dummyList = new ArrayList<>();
        String[] threatTypes = {"파라미터 조작 공격", "비정상 명령 주입", "통신 프로토콜 위반", "데이터 무결성 침해", "권한 상승 시도"};
        String[] sourceIps = {"192.168.10.45", "192.168.10.100", "192.168.10.78", "192.168.10.120", "192.168.10.33"};
        String[] destIps = {"192.168.10.80", "192.168.10.50", "192.168.10.90", "192.168.10.110"};

        Instant now = Instant.now();

        for (int i = 0; i < count; i++) {
            Threat threat = threats.get(random.nextInt(threats.size()));
            Instant timestamp = threat.getEventTimestamp() != null
                    ? threat.getEventTimestamp()
                    : now.minus(random.nextInt(7 * 24 * 60), ChronoUnit.MINUTES);

            XaiAnalysis analysis = XaiAnalysis.builder()
                    .timestamp(timestamp)
                    .threatType(threat.getThreatType() == null || threat.getThreatType().isBlank()
                            ? threatTypes[random.nextInt(threatTypes.length)]
                            : threat.getThreatType())
                    .sourceIp(threat.getSourceIp() != null ? threat.getSourceIp()
                            : sourceIps[random.nextInt(sourceIps.length)])
                    .destinationAssetIp(threat.getDestinationIp() != null ? threat.getDestinationIp()
                            : destIps[random.nextInt(destIps.length)])
                    .threatId(threat.getThreatId())
                    .threatIndex(threat.getThreatIndex())
                    .detectionDetails(generateDetectionDetails())
                    .violation(generateViolation())
                    .conclusion(generateConclusion())
                    .build();

            dummyList.add(analysis);
        }

        xaiAnalysisRepository.saveAll(dummyList);
        log.info("{}건의 더미 XAI 분석 데이터를 생성했습니다.", count);
    }

    private String generateDetectionDetails() {
        return "P_0002 패턴(고정 값 트리플)에서 의미론적 변형이 감지되었습니다. "
                + "실제 패킷 분석 결과, addr 필드의 높은 복원 오차가 탐지되었으며, "
                + "이는 실제 패킷의 명령 값이 정상 패턴과 크게 벗어났음을 나타냅니다.";
    }

    private String generateViolation() {
        return "정상 패턴에서 지정된 설정값 대신 비정상 값이 설정되어, "
                + "설정값 무단 변경을 통해 프로세스 흐름을 왜곡했습니다.";
    }

    private String generateConclusion() {
        return "잘못된 설정값 입력으로 인해 장비가 예상치 못한 동작을 할 수 있으며, "
                + "과부하가 걸려 장비 손상 및 생산 중단을 야기할 수 있습니다.";
    }

    private Optional<Threat> resolveThreat(XaiAnalysisDTO dto, Instant timestamp) {
        // 1순위: threatIndex로 매칭
        if (dto.getThreatIndex() != null) {
            var byIndex = threatRepository.findByThreatIndex(dto.getThreatIndex());
            if (byIndex.isPresent()) {
                log.info("✅ Threat 매칭 성공 (by index): threatIndex={}", dto.getThreatIndex());
                return byIndex;
            }
        }

        Optional<Threat> byExactTimestamp = matchThreatByExactTimestamp(dto.getTimestamp());
        if (byExactTimestamp.isPresent()) {
            log.info("✅ Threat 매칭 성공 (by timestamp string): {}", dto.getTimestamp());
            return byExactTimestamp;
        }

        // 2순위: timestamp 기준 유연한 매칭 (±5초 범위 내)
        if (timestamp != null) {
            Instant startTime = timestamp.minus(5, ChronoUnit.SECONDS);
            Instant endTime = timestamp.plus(5, ChronoUnit.SECONDS);

            List<Threat> candidates = threatRepository.findAll().stream()
                    .filter(t -> t.getEventTimestamp() != null)
                    .filter(t -> !t.getEventTimestamp().isBefore(startTime) &&
                                 !t.getEventTimestamp().isAfter(endTime))
                    .collect(Collectors.toList());

            if (!candidates.isEmpty()) {
                // threatType이 일치하는 것 우선
                if (dto.getThreatType() != null && !dto.getThreatType().isBlank()) {
                    Optional<Threat> withType = candidates.stream()
                            .filter(t -> dto.getThreatType().equals(t.getThreatType()))
                            .findFirst();
                    if (withType.isPresent()) {
                        log.info("✅ Threat 매칭 성공 (by timestamp range + type): timestamp={}, threatType={}",
                                timestamp, dto.getThreatType());
                        return withType;
                    }
                }

                // 가장 가까운 시간의 threat 선택
                Threat closest = candidates.stream()
                        .min((t1, t2) -> {
                            long diff1 = Math.abs(ChronoUnit.MILLIS.between(timestamp, t1.getEventTimestamp()));
                            long diff2 = Math.abs(ChronoUnit.MILLIS.between(timestamp, t2.getEventTimestamp()));
                            return Long.compare(diff1, diff2);
                        })
                        .orElse(null);

                if (closest != null) {
                    log.info("✅ Threat 매칭 성공 (by closest timestamp): timestamp={}, matched={}",
                            timestamp, closest.getEventTimestamp());
                    return Optional.of(closest);
                }
            }
        }

        log.warn("❌ 연결된 위협을 찾지 못했습니다. timestamp={}, threatType={}, index={}",
                dto.getTimestamp(), dto.getThreatType(), dto.getThreatIndex());
        return Optional.empty();
    }

    private Optional<Threat> matchThreatByExactTimestamp(String rawTimestamp) {
        if (rawTimestamp == null || rawTimestamp.isBlank()) {
            return Optional.empty();
        }
        String normalized = normalizeTimestampString(rawTimestamp);
        if (normalized == null) {
            return Optional.empty();
        }

        // 우선적으로 Instant 비교
        try {
            Instant parsed = Instant.parse(normalized);
            Optional<Threat> direct = threatRepository.findByEventTimestamp(parsed);
            if (direct.isPresent()) {
                return direct;
            }
        } catch (Exception ignored) {
        }

        // 동일한 문자열 표현을 갖는 Threat 탐색
        return threatRepository.findAll().stream()
                .filter(t -> t.getEventTimestamp() != null)
                .filter(t -> normalized.equals(normalizeTimestampString(t.getEventTimestamp())))
                .findFirst();
    }

    private String normalizeTimestampString(String rawTimestamp) {
        String trimmed = rawTimestamp.trim();
        try {
            return Instant.parse(trimmed).toString();
        } catch (Exception e) {
            return trimmed;
        }
    }

    private String normalizeTimestampString(Instant instant) {
        if (instant == null) {
            return null;
        }
        return instant.toString();
    }

    private void synchronizeThreatType(Threat threat, XaiAnalysisDTO dto) {
        String incomingType = dto.getThreatType();
        if (incomingType == null || incomingType.isBlank()) {
            return;
        }

        String existingType = threat.getThreatType();
        if (incomingType.equals(existingType)) {
            return;
        }

        threat.setThreatType(incomingType);
        threatRepository.save(threat);
        log.info("🔄 Threat {} 의 유형을 '{}' 로 갱신했습니다.", threat.getThreatId(), incomingType);
    }

    private Instant parseTimestamp(String timestamp) {
        if (timestamp == null || timestamp.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(timestamp);
        } catch (Exception e) {
            log.warn("XAI 타임스탬프 파싱 실패: {}", timestamp);
            return null;
        }
    }

    private void notifyRealtimeUpdates(List<XaiAnalysis> analyses) {
        if (analyses == null || analyses.isEmpty()) {
            return;
        }

        Set<String> threatIds = analyses.stream()
                .map(XaiAnalysis::getThreatId)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        if (threatIds.isEmpty()) {
            return;
        }

        String eventTimestamp = Instant.now().toString();
        threatIds.forEach(threatId -> {
            Map<String, Object> payload = Map.of(
                    "type", "xai_analysis_ready",
                    "threatId", threatId,
                    "timestamp", eventTimestamp
            );
            sseService.sendAnalysis(payload);
        });
    }
}
