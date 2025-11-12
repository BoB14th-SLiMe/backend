package com.ot.security.service;

import com.ot.security.dto.XaiAnalysisDTO;
import com.ot.security.entity.XaiAnalysis;
import com.ot.security.repository.XaiAnalysisRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class XaiAnalysisService {

    private final XaiAnalysisRepository xaiAnalysisRepository;

    @Transactional
    public void saveXaiAnalyses(List<XaiAnalysisDTO> analysisList) {
        List<XaiAnalysis> entities = analysisList.stream()
                .map(this::mapDtoToEntity)
                .collect(Collectors.toList());
        
        xaiAnalysisRepository.saveAll(entities);
        log.info("{} 건의 XAI 분석 결과를 저장했습니다.", entities.size());
    }

    private XaiAnalysis mapDtoToEntity(XaiAnalysisDTO dto) {
        return XaiAnalysis.builder()
                .timestamp(Instant.parse(dto.getTimestamp()))
                .threatType(dto.getThreatType())
                .sourceIp(dto.getSourceIp())
                .destinationAssetIp(dto.getDestinationAssetIp())
                .detectionEngine(dto.getDetectionEngine())
                .status(dto.getStatus())
                .detectionDetails(dto.getAnalysis() != null ? dto.getAnalysis().getDetectionDetails() : null)
                .violation(dto.getAnalysis() != null ? dto.getAnalysis().getViolation() : null)
                .conclusion(dto.getAnalysis() != null ? dto.getAnalysis().getConclusion() : null)
                .build();
    }
}