-- Score 기준으로 threat_level을 올바르게 업데이트
-- score >= 50 -> 'warning' (긴급)
-- score < 50 -> 'attention' (경고)

UPDATE threats
SET threat_level = CASE
    WHEN score >= 50 THEN 'warning'
    ELSE 'attention'
END
WHERE threat_level IS NULL
   OR threat_level NOT IN ('warning', 'attention')
   OR (score >= 50 AND threat_level != 'warning')
   OR (score < 50 AND threat_level != 'attention');

-- 업데이트 결과 확인
SELECT
    threat_id,
    threat_index,
    score,
    threat_level,
    status,
    detection_engine,
    event_timestamp
FROM threats
WHERE status = '신규'
ORDER BY event_timestamp DESC
LIMIT 20;
