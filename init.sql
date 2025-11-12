-- ================================================
-- OT 보안 모니터링 시스템 - 초기 스키마 및 데이터
-- ================================================

-- 알람 관리
CREATE TABLE IF NOT EXISTS alarms (
  id BIGSERIAL PRIMARY KEY,
  threat_id VARCHAR(255) UNIQUE NOT NULL,
  severity VARCHAR(20),
  status VARCHAR(20) DEFAULT 'unconfirmed',
  created_at TIMESTAMP DEFAULT NOW(),
  confirmed_at TIMESTAMP,
  resolved_at TIMESTAMP
);

CREATE INDEX idx_alarms_status ON alarms(status);
CREATE INDEX idx_alarms_severity ON alarms(severity);

-- 관리자 사후조치
CREATE TABLE IF NOT EXISTS admin_actions (
  id BIGSERIAL PRIMARY KEY,
  threat_id VARCHAR(255) UNIQUE NOT NULL,
  status VARCHAR(20) DEFAULT '미작성',
  author VARCHAR(100),
  content TEXT,
  completed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
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
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_assets_asset_id ON assets(asset_id);
CREATE INDEX idx_assets_ip_address ON assets(ip_address);

-- 자산 상태
CREATE TABLE IF NOT EXISTS asset_status (
  asset_id VARCHAR(50) PRIMARY KEY,
  status VARCHAR(20),
  last_seen TIMESTAMP,
  last_threat_id VARCHAR(255),
  updated_at TIMESTAMP DEFAULT NOW()
);

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
    timestamp TIMESTAMP,
    threat_type VARCHAR(255),
    source_ip VARCHAR(45),
    destination_asset_ip VARCHAR(45),
    detection_engine VARCHAR(100),
    status VARCHAR(50),
    detection_details TEXT,
    violation TEXT,
    conclusion TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_xai_analysis_timestamp ON xai_analysis(timestamp);
CREATE INDEX idx_xai_analysis_threat_type ON xai_analysis(threat_type);

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

-- 샘플 자산 데이터
INSERT INTO assets (asset_type, asset_id, ip_address, mac_address, name, position_x, position_y, is_visible) VALUES
  ('scada', 'SCADA-001', '192.168.0.2', '00:1A:2B:3C:4D:5E', 'SCADA 메인', 500, 100, true),
  ('switch', 'SWITCH-001', '192.168.0.1', '00:1A:2B:3C:4D:5F', 'Core Switch', 500, 300, true),
  ('plc', 'PLC-101', '192.168.0.101', 'AA:BB:CC:DD:EE:01', 'PLC-101', 200, 500, true),
  ('plc', 'PLC-102', '192.168.0.102', 'AA:BB:CC:DD:EE:02', 'PLC-102', 400, 500, true),
  ('plc', 'PLC-103', '192.168.0.103', 'AA:BB:CC:DD:EE:03', 'PLC-103', 600, 500, true),
  ('plc', 'PLC-104', '192.168.0.104', 'AA:BB:CC:DD:EE:04', 'PLC-104', 800, 500, true),
  ('hmi', 'HMI-001', '192.168.0.50', 'BB:CC:DD:EE:FF:01', 'HMI-001', 300, 200, true),
  ('hmi', 'HMI-002', '192.168.0.51', 'BB:CC:DD:EE:FF:02', 'HMI-002', 700, 200, true)
ON CONFLICT (asset_id) DO NOTHING;

-- 자산 상태 초기화
INSERT INTO asset_status (asset_id, status, last_seen, updated_at)
SELECT asset_id, 'normal', NOW(), NOW()
FROM assets
ON CONFLICT (asset_id) DO NOTHING;

-- 완료 메시지
SELECT 'OT Security Database Initialized Successfully!' AS message;