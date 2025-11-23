-- ================================================
-- ================================================

-- 위협 이벤트 (AI PC → Backend)
CREATE TABLE IF NOT EXISTS threats (
  threat_id VARCHAR(255) PRIMARY KEY,
  threat_index INT UNIQUE NOT NULL,
  detection_engine VARCHAR(20) NOT NULL,
  event_timestamp TIMESTAMP NOT NULL,
  source_ip VARCHAR(45),
  source_asset VARCHAR(100),
  destination_ip VARCHAR(45),
  destination_asset VARCHAR(100),
  threat_type VARCHAR(255) DEFAULT '',
  threat_level VARCHAR(20) DEFAULT 'warning',
  status VARCHAR(20) DEFAULT '신규',
  score DOUBLE PRECISION DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_threats_event_timestamp ON threats(event_timestamp DESC);
CREATE INDEX idx_threats_detection_engine ON threats(detection_engine);
CREATE INDEX idx_threats_level ON threats(threat_level);
CREATE INDEX idx_threats_status ON threats(status);

ALTER TABLE threats
  ADD COLUMN IF NOT EXISTS score DOUBLE PRECISION DEFAULT 0;

-- 관리자 사후조치
CREATE TABLE IF NOT EXISTS admin_actions (
  id BIGSERIAL PRIMARY KEY,
  threat_id VARCHAR(255) UNIQUE NOT NULL,
  status VARCHAR(20) DEFAULT '미작성',
  author VARCHAR(100),
  content TEXT,
  completed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  CONSTRAINT fk_admin_actions_threat
    FOREIGN KEY (threat_id) REFERENCES threats(threat_id)
    ON DELETE CASCADE
);

CREATE INDEX idx_admin_actions_threat_id ON admin_actions(threat_id);

-- 자산 관리
CREATE TABLE IF NOT EXISTS assets (
  id BIGSERIAL PRIMARY KEY,
  asset_type VARCHAR(20),
  asset_id VARCHAR(50) UNIQUE NOT NULL,
  ip_address VARCHAR(45),
  mac_address VARCHAR(17),
  name VARCHAR(100),
  position_x INT,
  position_y INT,
  is_visible BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  status VARCHAR(20) DEFAULT 'normal',
  last_seen TIMESTAMP
);

CREATE INDEX idx_assets_asset_id ON assets(asset_id);
CREATE INDEX idx_assets_ip_address ON assets(ip_address);

-- 시스템 설정
CREATE TABLE IF NOT EXISTS system_settings (
  id INT PRIMARY KEY DEFAULT 1,
  auto_refresh_interval INT DEFAULT 30,
  data_retention_days INT DEFAULT 90,
  cpu_threshold INT DEFAULT 80,
  ram_threshold INT DEFAULT 85,
  gpu_threshold INT DEFAULT 90,
  updated_at TIMESTAMP DEFAULT NOW(),
  CONSTRAINT single_row CHECK (id = 1)
);

-- 배너 메트릭 설정
CREATE TABLE IF NOT EXISTS banner_metrics_config (
  id BIGSERIAL PRIMARY KEY,
  metric_key VARCHAR(50) UNIQUE NOT NULL,
  label VARCHAR(100),
  is_enabled BOOLEAN DEFAULT true,
  display_order INT,
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_banner_metrics_enabled ON banner_metrics_config(is_enabled);
CREATE INDEX idx_banner_metrics_order ON banner_metrics_config(display_order);

-- XAI 분석 결과
CREATE TABLE IF NOT EXISTS xai_analysis (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMP NOT NULL,
  threat_id VARCHAR(255),
  threat_index INT,
  threat_type VARCHAR(255),
  source_ip VARCHAR(45),
  destination_asset_ip VARCHAR(45),
  detection_details TEXT,
  violation TEXT,
  conclusion TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  CONSTRAINT fk_xai_threat
    FOREIGN KEY (threat_id) REFERENCES threats(threat_id)
    ON DELETE SET NULL,
  CONSTRAINT fk_xai_threat_index
    FOREIGN KEY (threat_index) REFERENCES threats(threat_index)
    ON DELETE SET NULL
);

CREATE INDEX idx_xai_analysis_timestamp ON xai_analysis(timestamp DESC);
CREATE INDEX idx_xai_analysis_threat_type ON xai_analysis(threat_type);
CREATE INDEX idx_xai_analysis_threat_id ON xai_analysis(threat_id);


-- ================================================
-- 초기 데이터 삽입
-- ================================================

-- 시스템 설정 기본값
INSERT INTO system_settings (id, auto_refresh_interval, data_retention_days, cpu_threshold, ram_threshold, gpu_threshold)
VALUES (1, 30, 90, 80, 85, 90)
ON CONFLICT (id) DO NOTHING;

-- 배너 메트릭 기본값
INSERT INTO banner_metrics_config (metric_key, label, is_enabled, display_order) VALUES
  ('threat_score', '위협 점수', true, 1),
  ('anomaly_day', '이상탐지(Day)', true, 2),
  ('anomaly_week', '이상탐지(Week)', true, 3),
  ('new_ip', '새롭게 탐지된 IP', true, 4),
  ('unconfirmed_terminal', '미확인 알람', true, 5),
  ('critical_alert', '긴급 알람', true, 6),
  ('cpu', 'CPU 사용량', true, 7),
  ('ram', 'RAM 사용량', true, 8),
  ('gpu', 'GPU 사용량', true, 9)
ON CONFLICT (metric_key) DO NOTHING;

-- 실제 자산 데이터
INSERT INTO assets (asset_type, asset_id, ip_address, mac_address, name, position_x, position_y, is_visible, created_at, status, last_seen) VALUES
  -- 스위치 Management
  ('switch', 'SWITCH-001', '192.168.1.1', '00:1A:2B:3C:01:01', '스위치 Management', 100, 100, true, NOW(), 'normal', NOW()),
  ('switch', 'SWITCH-002', '192.168.1.10', '00:1A:2B:3C:01:0A', '스위치 Management', 200, 100, true, NOW(), 'normal', NOW()),
  ('switch', 'SWITCH-003', '192.168.1.11', '00:1A:2B:3C:01:0B', '스위치 Management', 300, 100, true, NOW(), 'normal', NOW()),
  ('switch', 'SWITCH-004', '192.168.1.133', '00:1A:2B:3C:01:85', '스위치 Management', 400, 100, true, NOW(), 'normal', NOW()),
  ('switch', 'SWITCH-005', '192.168.1.158', '00:1A:2B:3C:01:9E', '스위치 Management', 500, 100, true, NOW(), 'normal', NOW()),
  ('switch', 'SWITCH-006', '192.168.1.184', '00:1A:2B:3C:01:B8', '스위치 Management', 600, 100, true, NOW(), 'normal', NOW()),
  ('switch', 'SWITCH-007', '192.168.1.233', '00:1A:2B:3C:01:E9', '스위치 Management', 700, 100, true, NOW(), 'normal', NOW()),
  ('switch', 'SWITCH-008', '192.168.1.245', '00:1A:2B:3C:01:F5', '스위치 Management', 800, 100, true, NOW(), 'normal', NOW()),
  ('switch', 'SWITCH-009', '192.168.1.254', '00:1A:2B:3C:01:FE', '스위치 Management', 900, 100, true, NOW(), 'normal', NOW()),

  -- 서버
  ('server', 'SERVER-AD', '192.168.10.100', '00:1A:2B:10:01:00', 'Active Directory 서버', 100, 300, true, NOW(), 'normal', NOW()),
  ('server', 'SERVER-BACKUP', '192.168.10.101', '00:1A:2B:10:01:01', '백업 서버', 200, 300, true, NOW(), 'normal', NOW()),
  ('server', 'SERVER-PENTEST', '192.168.10.102', '00:1A:2B:10:01:02', '모의 침투 테스트 서버', 300, 300, true, NOW(), 'normal', NOW()),
  ('server', 'SERVER-MES', '192.168.10.103', '00:1A:2B:10:01:03', '통합 공정 관리 시스템 서버', 400, 300, true, NOW(), 'normal', NOW()),
  ('server', 'SERVER-MAIL', '192.168.10.106', '00:1A:2B:10:01:06', 'Mail Server', 500, 300, true, NOW(), 'normal', NOW()),
  ('server', 'SERVER-COVERITY', '192.168.10.202', '00:1A:2B:10:02:02', 'Coverity Server', 600, 300, true, NOW(), 'normal', NOW()),
  ('server', 'SERVER-NTP', '194.0.5.123', '00:1A:2B:C2:05:7B', 'NTP 서버', 700, 300, true, NOW(), 'normal', NOW()),

  -- PLC
  ('plc', 'PLC-LS', '192.168.10.15', 'AA:BB:CC:10:00:15', 'LS Electric PLC', 100, 500, true, NOW(), 'normal', NOW()),
  ('plc', 'PLC-MITSU-HIDDEN', '192.168.10.39', 'AA:BB:CC:10:00:39', 'Mitsubishi PLC (Hidden)', 200, 500, true, NOW(), 'normal', NOW()),
  ('plc', 'PLC-MITSU-WALL', '192.168.10.45', 'AA:BB:CC:10:00:45', 'Mitsubishi PLC (Wall)', 300, 500, true, NOW(), 'normal', NOW()),
  ('plc', 'PLC-SIEMENS', '192.168.10.47', 'AA:BB:CC:10:00:47', 'Siemens PLC', 400, 500, true, NOW(), 'normal', NOW()),

  -- HMI
  ('hmi', 'HMI-BLENDING', '192.168.10.80', 'BB:CC:DD:10:00:80', 'HMI 1(Blending)', 100, 700, true, NOW(), 'normal', NOW()),
  ('hmi', 'HMI-LABELING', '192.168.10.81', 'BB:CC:DD:10:00:81', 'HMI 2(Labeling)', 200, 700, true, NOW(), 'normal', NOW()),
  ('hmi', 'HMI-ROBOT', '192.168.10.82', 'BB:CC:DD:10:00:82', 'HMI 3(Robot)', 300, 700, true, NOW(), 'normal', NOW()),

  -- PC/Workstation
  ('workstation', 'PC-TARGET', '192.168.10.105', 'CC:DD:EE:10:01:05', '공격 대상 PC', 500, 500, true, NOW(), 'normal', NOW()),
  ('workstation', 'LAPTOP-ASUS', '192.168.10.151', 'CC:DD:EE:10:01:51', 'ASUS Laptop', 600, 500, true, NOW(), 'normal', NOW()),
  ('workstation', 'PC-OT-DATA', '192.168.10.171', 'CC:DD:EE:10:01:71', 'OT 데이터 수집 PC', 700, 500, true, NOW(), 'normal', NOW()),
  ('workstation', 'LAPTOP-LG', '192.168.10.172', 'CC:DD:EE:10:01:72', 'LG Laptop', 800, 500, true, NOW(), 'normal', NOW()),
  ('workstation', 'LAPTOP-METASPLOIT', '192.168.10.33', 'CC:DD:EE:10:00:33', 'Metasploit Laptop', 900, 500, true, NOW(), 'normal', NOW())
ON CONFLICT (asset_id) DO NOTHING;

-- 위협 이벤트 더미 데이터
-- threat_level: score >= 50 = 'warning' (긴급), score < 50 = 'attention' (경고)
INSERT INTO threats (threat_id, threat_index, detection_engine, event_timestamp, source_ip, source_asset, destination_ip, destination_asset, threat_type, threat_level, status, score) VALUES
  ('THREAT-0001', 1001, 'RULE', '2024-02-25 09:30:00+00', '192.168.10.21', 'PLC-201', '192.168.10.2', 'SCADA 메인', '', 'warning', '신규', 92.5),
  ('THREAT-0002', 1002, 'ML',   '2024-02-25 09:32:15+00', '192.168.10.45', 'PLC-205', '192.168.10.5', '제어 서버', '', 'warning', '신규', 67.0),
  ('THREAT-0003', 1003, 'DL',   '2024-02-25 09:35:40+00', '192.168.10.77', '센서 허브', '192.168.10.60', '데이터 수집기', '', 'warning', '신규', 88.1),
  ('THREAT-0004', 1004, 'RULE', '2024-02-25 09:41:05+00', '192.168.10.88', '현장 HMI', '192.168.10.2', 'SCADA 메인', '', 'attention', '신규', 45.0),
  ('THREAT-0005', 1005, 'ML',   '2024-02-25 09:45:20+00', '192.168.10.101', 'PLC-210', '192.168.10.50', 'HMI-001', '', 'warning', '신규', 51.2)
ON CONFLICT (threat_id) DO NOTHING;

-- XAI 분석 샘플 데이터 (timestamp 기준 매핑)
INSERT INTO xai_analysis (timestamp, threat_id, threat_index, threat_type, source_ip, destination_asset_ip, detection_details, violation, conclusion) VALUES
  ('2024-02-25 09:30:00+00', 'THREAT-0001', 1001, '', '192.168.10.21', '192.168.10.2',
   'AI-PC RULE 모델이 PLC-201의 Modbus 쓰기 패턴에서 이상치를 감지했습니다.',
   '권한 없는 파라미터 변경 시도가 확인되었습니다.',
   '설정값 무결성 검토 및 현장 설비 확인이 필요합니다.'),
  ('2024-02-25 09:32:15+00', 'THREAT-0002', 1002, '', '192.168.10.45', '192.168.10.5',
   'ML 모델이 반복적인 쓰기 명령을 비정상 시퀀스로 분류했습니다.',
   '설비 운영 정책을 위반한 제어 명령이 전달되었습니다.',
   '해당 시퀀스를 차단하고 운영자 확인을 진행하세요.'),
  ('2024-02-25 09:35:40+00', 'THREAT-0003', 1003, '', '192.168.10.77', '192.168.10.60',
   'DL 모델이 센서 허브에서 주입된 잡음 패턴을 탐지했습니다.',
   '데이터 수집기와의 통신 프로토콜 스펙을 위반했습니다.',
   '센서 채널을 점검하고 패킷 샘플을 보존하세요.'),
  ('2024-02-25 09:41:05+00', 'THREAT-0004', 1004, '', '192.168.10.88', '192.168.10.2',
   'RULE 엔진이 HMI 명령어에서 허용되지 않은 기능 코드를 확인했습니다.',
   'HMI 계정 권한을 초과한 명령 시도가 발생했습니다.',
   '사용자 인증 이력을 검토하고 세션을 강제 종료하세요.'),
  ('2024-02-25 09:45:20+00', 'THREAT-0005', 1005, '', '192.168.10.101', '192.168.10.50',
   'ML 모델이 PLC-210에서 평소 대비 3배 이상 패킷 폭주를 포착했습니다.',
   'HMI-001 대상 DoS 가능성이 있으며 가용성 저하가 우려됩니다.',
   '관련 네트워크 구간을 분리하고 방화벽 룰을 강화하세요.')
ON CONFLICT DO NOTHING;


-- 요약 지표 스냅샷 (단일 레코드)
CREATE TABLE IF NOT EXISTS summary_metrics (
  id INT PRIMARY KEY DEFAULT 1,
  safety_score INT DEFAULT 0,
  anomaly_day BIGINT DEFAULT 0,
  anomaly_week BIGINT DEFAULT 0,
  new_ip_count BIGINT DEFAULT 0,
  unconfirmed_alarms BIGINT DEFAULT 0,
  critical_alarms BIGINT DEFAULT 0,
  auto_refresh BOOLEAN DEFAULT false,
  updated_at TIMESTAMP DEFAULT NOW(),
  CONSTRAINT summary_metrics_single CHECK (id = 1)
);

-- 시스템 메트릭 테이블 (단일 레코드)
CREATE TABLE IF NOT EXISTS system_metrics (
  id INT PRIMARY KEY DEFAULT 1,
  timestamp TIMESTAMP DEFAULT NOW(),
  cpu_usage DOUBLE PRECISION DEFAULT 50.0,
  ram_usage DOUBLE PRECISION DEFAULT 50.0,
  gpu_usage DOUBLE PRECISION DEFAULT 50.0,
  source VARCHAR(100) DEFAULT 'AI-PC',
  CONSTRAINT single_metrics_row CHECK (id = 1)
);

-- 초기 메트릭 데이터
INSERT INTO system_metrics (id, cpu_usage, ram_usage, gpu_usage, source, timestamp)
VALUES (1, 50.0, 50.0, 50.0, 'AI-PC', NOW())
ON CONFLICT (id) DO NOTHING;

-- 완료 메시지
SELECT 'OT Security Database Initialized Successfully!' AS message;
