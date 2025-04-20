-- Indexes for threat_data
CREATE INDEX idx_threat_data_risk_score ON threat_data(risk_score);
CREATE INDEX idx_threat_data_description ON threat_data(description);