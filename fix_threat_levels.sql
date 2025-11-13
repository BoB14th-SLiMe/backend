-- 기존 threat_level 값을 score 기준으로 수정
-- score >= 50 = 'warning' (긴급)
-- score < 50 = 'attention' (경고)

UPDATE threats
SET threat_level = CASE
    WHEN score >= 50 THEN 'warning'
    ELSE 'attention'
END
WHERE threat_level IS NOT NULL OR threat_level != '';

-- 결과 확인
SELECT threat_id, threat_index, score, threat_level, status
FROM threats
ORDER BY threat_index;
