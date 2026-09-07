# Chakravyuh Sentinel - Deployment Guide

## Backend Deployment (Render)

### Prerequisites
- GitHub repository with `pre-deployment` branch
- Render account (free tier available)
- Netlify frontend URL (for CORS configuration)

### Step 1: Prepare Repository
1. Ensure all changes are committed to `pre-deployment` branch
2. Verify deployment files are present:
   - `Procfile`
   - `render.yaml`
   - `runtime.txt`
   - `requirements.txt`
   - `.env.example`

### Step 2: Deploy to Render

**IMPORTANT: Manual Setup Required**
Due to the subdirectory structure of the project, manual setup in Render dashboard is recommended over blueprint deployment.

#### Manual Setup (Recommended)
1. **Create PostgreSQL Database:**
   - Go to Render Dashboard → "New +" → "PostgreSQL"
   - Name: `chakravyuh-db`
   - Database: `chakravyuh_sentinel`
   - Region: Choose nearest to your users
   - Click "Create Database"

2. **Create Web Service:**
   - Go to Render Dashboard → "New +" → "Web Service"
   - Connect GitHub repository
   - Select `pre-deployment` branch
   - **Root Directory**: `chakrahvyuh-sentinel/HANDOVER/HANDOVER/chakravyuh_backend`
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Environment Variables**:
     - `DATABASE_URL`: (Render will auto-fill from database)
     - `SESSION_TIMEOUT_MINUTES`: `30`
     - `SESSION_EVAL_THRESHOLD`: `5`
     - `BLOCK_DURATION_MINUTES`: `60`
     - `CORS_ORIGINS`: `https://chakravyuh-sentinel.netlify.app,https://singhaman.me` (UPDATE THIS)
   - Click "Create Web Service"

### Step 3: Verify Deployment
1. Monitor deployment logs in Render Dashboard
2. Wait for deployment to complete (2-3 minutes)
3. Test the deployed API:
   ```bash
   curl https://your-api-url.onrender.com/stats
   ```
4. Test the new traffic ingestion endpoint:
   ```bash
   curl -X POST https://your-api-url.onrender.com/api/ingest-traffic \
     -H "Content-Type: application/json" \
     -d '{"ip":"192.168.1.100","method":"GET","endpoint":"/test","status_code":200,"timestamp":"2024-09-05T10:30:00Z"}'
   ```
5. Check that database tables are created automatically

### Step 4: Update Frontend Configuration
1. Get your deployed backend URL from Render
2. Update frontend `js/config.js`:
   ```javascript
   window.SENTINEL_CONFIG = {
     API_BASE: "https://your-api-url.onrender.com",
   };
   ```
3. Redeploy frontend to Netlify if needed

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string (Render provides this) |
| `SESSION_TIMEOUT_MINUTES` | No | 30 | Session inactivity timeout in minutes |
| `SESSION_EVAL_THRESHOLD` | No | 5 | Request count threshold for behavior evaluation |
| `BLOCK_DURATION_MINUTES` | No | 60 | IP block duration in minutes |
| `CORS_ORIGINS` | No | * | Comma-separated allowed origins for CORS |

## Troubleshooting

### Deployment Failures
- Check Render logs for specific error messages
- Ensure `requirements.txt` is in the correct directory
- Verify Python version compatibility (3.13.7)

### Database Connection Issues
- Verify `DATABASE_URL` is correctly set
- Check that PostgreSQL database is created and accessible
- Ensure database is in the same region as web service

### CORS Errors
- Verify `CORS_ORIGINS` includes your Netlify frontend URL
- Check that the URL starts with `https://` for production
- Clear browser cache if CORS configuration was recently changed

### ML Model Loading Issues
- Ensure all `.pkl` files are present in `models/` directory
- Verify `scikit-learn==1.6.1` is installed
- Check model file permissions

## Production Considerations

### Security
- Never commit `.env` file with real credentials
- Use strong database passwords (Render generates these automatically)
- Set specific `CORS_ORIGINS` for production (not `*`)
- Monitor security alerts regularly

### Performance
- Render free tier includes:
  - 512 MB RAM
  - 0.1 CPU
  - 90 GB SSD storage
- Upgrade to paid tier if needed for production traffic

### Monitoring
- Use Render's built-in metrics
- Monitor database connection pool usage
- Check error logs regularly
- Set up alerts for deployment failures

## Cost Estimate (Render Free Tier)

- **Web Service**: Free (with limitations)
- **PostgreSQL**: Free (90 days, then ~$7/month)
- **Total**: $0/month initially, ~$7/month after 90 days

For a final-year project, the free tier should be sufficient for demonstration purposes.