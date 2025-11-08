package com.ot.security.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
@Service
public class SSEService {

    @Value("${ot-security.sse.timeout}")
    private long sseTimeout;

    // Emitter 저장소
    private final CopyOnWriteArrayList<SseEmitter> emitters = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<SseEmitter> threatEmitters = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<SseEmitter> statsEmitters = new CopyOnWriteArrayList<>();

    /**
     * 일반 SSE Emitter 생성
     */
    public SseEmitter createEmitter() {
        SseEmitter emitter = new SseEmitter(sseTimeout);
        emitters.add(emitter);

        emitter.onCompletion(() -> {
            log.info("SSE 연결 완료");
            emitters.remove(emitter);
        });

        emitter.onTimeout(() -> {
            log.info("SSE 연결 타임아웃");
            emitters.remove(emitter);
        });

        emitter.onError(e -> {
            log.error("SSE 연결 오류", e);
            emitters.remove(emitter);
        });

        // 초기 연결 메시지
        try {
            emitter.send(SseEmitter.event()
                .name("connect")
                .data("SSE 연결 성공"));
        } catch (IOException e) {
            log.error("초기 메시지 전송 실패", e);
        }

        return emitter;
    }

    /**
     * 위협 전용 SSE Emitter 생성
     */
    public SseEmitter createThreatEmitter() {
        SseEmitter emitter = new SseEmitter(sseTimeout);
        threatEmitters.add(emitter);

        emitter.onCompletion(() -> threatEmitters.remove(emitter));
        emitter.onTimeout(() -> threatEmitters.remove(emitter));
        emitter.onError(e -> threatEmitters.remove(emitter));

        try {
            emitter.send(SseEmitter.event()
                .name("connect")
                .data("위협 이벤트 SSE 연결 성공"));
        } catch (IOException e) {
            log.error("초기 메시지 전송 실패", e);
        }

        return emitter;
    }

    /**
     * 통계 전용 SSE Emitter 생성
     */
    public SseEmitter createStatsEmitter() {
        SseEmitter emitter = new SseEmitter(sseTimeout);
        statsEmitters.add(emitter);

        emitter.onCompletion(() -> statsEmitters.remove(emitter));
        emitter.onTimeout(() -> statsEmitters.remove(emitter));
        emitter.onError(e -> statsEmitters.remove(emitter));

        try {
            emitter.send(SseEmitter.event()
                .name("connect")
                .data("통계 SSE 연결 성공"));
        } catch (IOException e) {
            log.error("초기 메시지 전송 실패", e);
        }

        return emitter;
    }

    /**
     * 모든 클라이언트에게 이벤트 전송
     */
    public void sendToAll(String eventName, Object data) {
        sendToEmitters(emitters, eventName, data);
    }

    /**
     * 위협 이벤트 전송
     */
    public void sendThreat(Object data) {
        sendToEmitters(threatEmitters, "threat", data);
        sendToEmitters(emitters, "threat", data);  // 일반 구독자에게도 전송
    }

    /**
     * 통계 업데이트 전송
     */
    public void sendStats(Object data) {
        sendToEmitters(statsEmitters, "stats", data);
        sendToEmitters(emitters, "stats", data);  // 일반 구독자에게도 전송
    }

    /**
     * Emitter 목록에 이벤트 전송
     */
    private void sendToEmitters(CopyOnWriteArrayList<SseEmitter> emitterList, String eventName, Object data) {
        emitterList.forEach(emitter -> {
            try {
                emitter.send(SseEmitter.event()
                    .name(eventName)
                    .data(data));
            } catch (IOException e) {
                log.error("SSE 전송 실패", e);
                emitterList.remove(emitter);
            }
        });
    }

    /**
     * 하트비트 전송
     */
    public void sendHeartbeat() {
        Map<String, String> heartbeat = Map.of("type", "heartbeat", "timestamp", String.valueOf(System.currentTimeMillis()));
        sendToAll("heartbeat", heartbeat);
    }

    /**
     * 활성 연결 수 조회
     */
    public int getActiveConnections() {
        return emitters.size();
    }

    public int getActiveThreatConnections() {
        return threatEmitters.size();
    }

    public int getActiveStatsConnections() {
        return statsEmitters.size();
    }
}
