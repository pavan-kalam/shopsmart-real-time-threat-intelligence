CREATE TABLE threat_data (
    id SERIAL PRIMARY KEY,  -- Unique identifier for threat entry
    threat_type VARCHAR(255) NOT NULL,  -- Type of threat (e.g., phishing, malware, DDoS)
    source_name VARCHAR(255) NOT NULL,  -- Name of the OSINT source (e.g., Twitter, ThreatFeed)
    source_url TEXT,  -- URL of the source (if applicable)
    description TEXT NOT NULL,  -- Description of the threat
    severity_level VARCHAR(50),  -- Severity level (e.g., Low, Medium, High, Critical)
    confidence_level VARCHAR(50),  -- Confidence level (e.g., Low, Medium, High)
    first_seen TIMESTAMP NOT NULL,  -- When the threat was first observed
    last_updated TIMESTAMP NOT NULL,  -- When the threat data was last updated
    affected_assets TEXT,  -- List of affected assets (e.g., IPs, domains, URLs)
    mitigation_recommendations TEXT,  -- Recommended actions to mitigate the threat
    tags TEXT[],  -- Tags for categorization (e.g., ["phishing", "financial"])
    is_active BOOLEAN DEFAULT TRUE,  -- Whether the threat is still active
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- When the record was created
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- When the record was last updated
);

-- Indexes for faster querying
CREATE INDEX idx_threat_type ON threat_data (threat_type);
CREATE INDEX idx_severity_level ON threat_data (severity_level);
CREATE INDEX idx_first_seen ON threat_data (first_seen);
CREATE INDEX idx_is_active ON threat_data (is_active);