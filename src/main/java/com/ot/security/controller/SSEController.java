package com.ot.security.controller;

import com.ot.security.service.SSEService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@Slf4j
@RestController
@RequestMapping("/api/sse")
@RequiredArgsConstructor
@Tag(name = "SSE", description = "Server-Sent Events API")
public class SSEController {

    private final SSEService sseService;

    @GetMapping(value = "/subscribe", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @Operation(summary = "SSE 구독", description = "실시간 이벤트 스트림을 구독합니다.")
    public SseEmitter subscribe() {
        log.info("SSE 연결 요청");
        return sseService.createEmitter();
    }

    @GetMapping(value = "/threats", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @Operation(summary = "위협 이벤트 스트림", description = "실시간 위협 이벤트만 구독합니다.")
    public SseEmitter subscribeThreats() {
        log.info("위협 이벤트 SSE 연결 요청");
        return sseService.createThreatEmitter();
    }

    @GetMapping(value = "/stats", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @Operation(summary = "통계 스트림", description = "실시간 통계 데이터를 구독합니다.")
    public SseEmitter subscribeStats() {
        log.info("통계 SSE 연결 요청");
        return sseService.createStatsEmitter();
    }
}
