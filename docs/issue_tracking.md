# Issue Tracking Log

## GitHub Issues
- **Issue #1**: High-risk alerts not triggering emails
  - **Status**: Resolved
  - **Fix**: Updated SMTP configuration in alerts.py
  - **Verified**: Email sent successfully

- **Issue #2**: Dashboard filter not updating
  - **Status**: Resolved
  - **Fix**: Fixed useEffect dependencies in Dashboard.js
  - **Verified**: Filters update correctly

- **Issue #3**: Slow query performance
  - **Status**: Resolved
  - **Fix**: Added index on threat_data.created_at
  - **Verified**: Query time reduced from 150ms to 40ms
