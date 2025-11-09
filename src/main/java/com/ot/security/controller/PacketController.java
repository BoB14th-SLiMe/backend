package com.ot.security.controller;

import com.ot.security.entity.Packet;
import com.ot.security.service.ElasticsearchService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/packets")
@RequiredArgsConstructor
@Tag(name = "Packets", description = "패킷 데이터 API")
public class PacketController {

    private final ElasticsearchService elasticsearchService;

    @GetMapping
    @Operation(summary = "패킷 목록 조회", description = "페이징된 패킷 목록을 조회합니다.")
    public ResponseEntity<List<Packet>> getPackets(
        @Parameter(description = "페이지 번호 (0부터 시작)")
        @RequestParam(defaultValue = "0") int page,
        
        @Parameter(description = "페이지 크기")
        @RequestParam(defaultValue = "20") int size
    ) {
        try {
            int from = page * size;
            List<Packet> packets = elasticsearchService.searchPackets(from, size);
            return ResponseEntity.ok(packets);
        } catch (IOException e) {
            log.error("패킷 조회 실패", e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
