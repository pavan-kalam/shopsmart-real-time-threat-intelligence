-- db/assets.sql
CREATE TABLE assets (
    id SERIAL PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50) CHECK (asset_type IN ('Hardware', 'Software', 'Data', 'People', 'Process')),
    description TEXT
);

-- Insert sample assets
INSERT INTO assets (asset_name, asset_type, description) VALUES
('Web Server', 'Hardware', 'Primary server hosting the company website'),
('Customer Database', 'Software', 'Database storing customer records and transaction logs'),
('Employee Records', 'Data', 'Sensitive data containing employee information'),
('IT Staff', 'People', 'Internal IT team responsible for system maintenance'),
('Payment Processing', 'Process', 'Process for handling customer payments securely');