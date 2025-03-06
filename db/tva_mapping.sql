-- db/tva_mapping.sql
CREATE TABLE tva_mapping (
    id SERIAL PRIMARY KEY,
    asset_id INT REFERENCES assets(id) ON DELETE CASCADE,
    threat_name VARCHAR(255) NOT NULL,
    vulnerability_description TEXT NOT NULL,
    likelihood INT CHECK (likelihood BETWEEN 1 AND 5),
    impact INT CHECK (impact BETWEEN 1 AND 5),
    risk_score INT GENERATED ALWAYS AS (likelihood * impact) STORED
);

-- db/tva_mapping.sql
INSERT INTO tva_mapping (asset_id, threat_name, vulnerability_description, likelihood, impact) VALUES
(1, 'DDoS Attack', 'Web server vulnerable to DDoS attacks due to lack of rate limiting', 4, 5),
(2, 'SQL Injection', 'Customer database vulnerable to SQL injection attacks', 3, 5),
(3, 'Data Breach', 'Employee records exposed due to weak access controls', 2, 4),
(4, 'Phishing Attack', 'IT staff targeted by phishing emails', 3, 3),
(5, 'Payment Fraud', 'Payment processing system vulnerable to man-in-the-middle attacks', 4, 5);