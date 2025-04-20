# Deployment Checklist

## Server Security
- 1. Disabled root SSH login and password-based authentication
- 2. Configured EC2 security groups (ports 22, 80, 443, 5002)
- 3. Installed and configured AWS WAF (SQLi, XSS, rate-limiting rules)
- 4. Encrypted PostgreSQL data at rest
- 5. Secured Redis with password and localhost binding
- 6. Stored environment variables in AWS Secrets Manager

## Logging and Monitoring
- 1. Integrated logging with AWS CloudWatch (logs/*.log)
- 2. Configured SNS for high-risk alerts (ThreatIntelAlerts topic)
- 3. Added metrics for API response times and database performance

## Deployment
- 1. Transferred project.tar.gz to EC2
- 2. Installed backend (Python, Gunicorn) and frontend (Node.js, npm build) dependencies
- 3. Configured Gunicorn systemd service
- 4. Set up Nginx as reverse proxy with SSL (Certbot)
- 5. Verified dashboard at browser through EC2 public IP
- 6. Tested API endpoints (/api/spiderfoot/threatLogs, /api/real-time-alerts)
