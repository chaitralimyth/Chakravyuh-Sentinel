# Chakravyuh Sentinel — Behavior Pipeline Setup

## 1. Install dependencies

```bash
pip install -r requirements.txt
```

**Version note:** the `sentinel_behavior_model.pkl` / `label_encoder.pkl` files were
trained with scikit-learn 1.6.1. If you install a newer scikit-learn (e.g. 1.8.x),
you'll see an `InconsistentVersionWarning` at load time — it's a warning, not an
error, and predictions still run. If you see inconsistent results, pin the exact
training version instead:
```bash
pip install scikit-learn==1.6.1
```

## 2. Create the PostgreSQL database

Open a terminal with `psql` available (adjust the `postgres` superuser name if yours differs):

```bash
psql -U postgres
```

Inside the `psql` prompt:

```sql
CREATE DATABASE chakravyuh_sentinel;
CREATE USER chakravyuh_user WITH PASSWORD 'change_this_password';
GRANT ALL PRIVILEGES ON DATABASE chakravyuh_sentinel TO chakravyuh_user;
\q
```

## 3. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and set:
```
DATABASE_URL=postgresql+psycopg2://chakravyuh_user:change_this_password@localhost:5432/chakravyuh_sentinel
```

## 4. Place the model artifacts

Confirm these files exist in `models/` (already placed if you used the files from this conversation):
```
models/logistic-regression-model.pkl   (existing URL pipeline)
models/randomforest-model.pkl          (existing URL pipeline)
models/xgb_model.pkl                   (existing URL pipeline)
models/features-order.pkl              (existing URL pipeline)
models/sentinel_behavior_model.pkl     (new behavior pipeline)
models/feature_columns_behaviour.pkl   (new behavior pipeline)
models/label_encoder.pkl               (new behavior pipeline)
```

## 5. Initialize the tables

Tables are created automatically on app startup (`init_db()` runs in `main.py`'s
`@app.on_event("startup")` hook — `Base.metadata.create_all()` is a no-op for
tables that already exist, so this is safe to run repeatedly).

To create them without starting the full app (e.g. to inspect before running):

```bash
python3 -c "from app.database import init_db; init_db()"
```

Run this from the `project/` root, with `.env` configured, so `DATABASE_URL` resolves.

## 6. Run the app

```bash
uvicorn app.main:app --reload
```

## 7. Verify tables in pgAdmin

1. Open pgAdmin, connect to your local PostgreSQL server.
2. Expand **Databases → chakravyuh_sentinel → Schemas → public → Tables**.
3. You should see: `sessions`, `request_logs`, `blocked_ips`, `security_alerts`.
4. Right-click any table → **View/Edit Data → All Rows** to see live data as
   requests come in.
5. Or run in the pgAdmin Query Tool:
   ```sql
   SELECT * FROM sessions ORDER BY started_at DESC LIMIT 20;
   SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT 20;
   SELECT * FROM blocked_ips WHERE is_active = true;
   SELECT * FROM security_alerts ORDER BY created_at DESC LIMIT 20;
   ```

## 8. Testing

### 8a. Existing URL pipeline still works
```bash
curl -X POST "http://127.0.0.1:8000/predict?url=http://example.com"
```
Should return the same JSON shape as before (model_confidence, final_score, risk_level, action, reasons, request_count).

### 8b. Behavior model loads correctly
```bash
python3 -c "
from app.behavior_model_loader import behavior_model, behavior_feature_order, behavior_label_encoder
print(len(behavior_feature_order))          # expect 28
print(hasattr(behavior_model, 'predict_proba'))  # expect True
print(list(behavior_label_encoder.classes_))     # expect ['attacker', 'normal']
"
```

### 8c. Feature vector has exactly 28 values, in the correct order
```bash
python3 -c "
from app.behavior_feature_extractor import build_feature_vector
from app.behavior_model_loader import behavior_feature_order
vec = build_feature_vector([])   # empty session -> all zeros, still 28 values
assert len(vec) == 28
print('OK', len(vec))
print(behavior_feature_order)
"
```

### 8d. Normal session → ALLOW
Hit any existing route (e.g. `GET /`) fewer than `SESSION_EVAL_THRESHOLD` times with normal
timing — no evaluation fires yet, session stays active, no block/alert row created.
Then hit it `SESSION_EVAL_THRESHOLD` times total from the same IP; check `sessions` in
pgAdmin — `status` should still be `active` if the model classifies it `normal`.

### 8e. Attacker-like session → BLOCK
From the same IP, generate a burst of requests hitting many distinct endpoints (including
ones containing `/admin`), with 401/422 statuses if you have such routes, in quick
succession, until `request_count` hits a multiple of `SESSION_EVAL_THRESHOLD`. Check:
```sql
SELECT * FROM blocked_ips WHERE ip = 'YOUR_TEST_IP' AND is_active = true;
SELECT * FROM security_alerts WHERE ip = 'YOUR_TEST_IP' ORDER BY created_at DESC;
```
Both should have a new row with `prediction = 'attacker'`.

### 8f. Blocked IP → HTTP 403
Once blocked, any further request from that IP (any route) should return:
```json
{"detail": "Access blocked due to suspicious behavior."}
```
with status code 403 — response body:
```json
{"detail": "Forbidden: IP blocked by Sentinel"}
```
Dashboard read routes (`/stats`, `/alerts`, etc.) remain reachable even when the caller IP is blocked.

### 8g. Block expires
```sql
UPDATE blocked_ips SET blocked_until = NOW() - INTERVAL '1 minute' WHERE ip = 'YOUR_TEST_IP';
```
Next request from that IP should pass through (auto-expired by `is_ip_blocked()`).

## 9. Dashboard API & Frontend

### 9a. Dashboard read-only endpoints

With the backend running on port 8000:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/stats` | KPI summary (requests, sessions, alerts, blocked IPs) |
| GET | `/statistics` | Chart/analytics data (7-day trends, status codes, top IPs) |
| GET | `/alerts?limit=100` | Security alerts list |
| GET | `/blocked-ips?active_only=true` | Blocked IP records |
| GET | `/requests?limit=100` | Request log entries |
| GET | `/sessions?limit=100` | Session records |

Quick smoke test:

```bash
python test_dashboard_api.py
```

Or curl each endpoint:

```bash
curl http://127.0.0.1:8000/stats
curl http://127.0.0.1:8000/alerts
curl http://127.0.0.1:8000/blocked-ips
curl http://127.0.0.1:8000/requests
curl http://127.0.0.1:8000/sessions
curl http://127.0.0.1:8000/statistics
```

### 9b. Open the admin dashboard

The dashboard is static HTML under `sentinel_security_dashboard/stitch_sentinel_security_dashboard/`.

1. Start the backend: `uvicorn app.main:app --reload` (default `http://127.0.0.1:8000`)
2. Serve the dashboard folder with any static file server, e.g.:
   ```bash
   cd sentinel_security_dashboard/stitch_sentinel_security_dashboard
   python -m http.server 5500
   ```
3. Open `http://127.0.0.1:5500/index.html` (redirects to Dashboard Overview)

The frontend reads from `http://127.0.0.1:8000` by default. To change the API URL, run in the browser console:

```javascript
localStorage.setItem('SENTINEL_API_BASE', 'http://127.0.0.1:8000');
```

CORS is enabled for all origins so the dashboard can fetch from a different port.
