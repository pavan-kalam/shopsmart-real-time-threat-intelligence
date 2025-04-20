# Troubleshooting Guide

## Common Issues

### Backend
- **SpiderFoot Returns No Data**
  - **Symptoms**: `fetch_spiderfoot_data` logs "No data returned for query".
  - **Fix**:
    1. Start the docker engine and ensure the Spiderfoot container is running.
    2. Verify SpiderFoot CLI is installed Docker (`spiderfoot --version`).
    3. Check query format in `spiderfoot.py`.
    4. Ensure `temp_dir` is writable.
  
### Database Connection Error
- **Symptoms**: logger.error("Database connection error") in fetch_osint.py.
- **Fix**:
  1. Verify PostgreSQL is running (psql -U shopsmart -d shopsmart).
  2. Check DATABASE_URL in .env.
  3. Restart PostgreSQL.

### Frontend
- **Dashboard Data Not Loading**
  - **Symptoms**: Blank dashboard or "Error fetching data" in console.
  - **Fix**:
    1. Verify API endpoint (http://localhost:5002/api/spiderfoot/threatLogs).
    2. Check CORS settings in app.py.
    3. Clear browser cache or test in incognito mode.

### Database
- **Slow Queries**
  - **Symptoms**: High latency in threat_data queries.
  - **Fix**:
    1. Run EXPLAIN ANALYZE on slow queries.
    2. Apply indexes from query_optimizations.sql.
    3. Optimize save_threat_data with bulk inserts.