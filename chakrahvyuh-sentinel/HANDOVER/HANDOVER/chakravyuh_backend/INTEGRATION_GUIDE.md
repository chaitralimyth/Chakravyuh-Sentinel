# Chakravyuh Sentinel Traffic Ingestion Integration Guide

## Overview
This guide provides the integration details for connecting `https://singhaman.me` with the deployed Chakravyuh Sentinel backend to enable traffic monitoring and security analysis.

## Production Endpoint
**URL:** `https://chakravyuh-sentinel.onrender.com/api/ingest-traffic`

**Method:** `POST`

## Request Schema
The endpoint expects a JSON request body with the following structure:

```json
{
  "ip": "string (required)",
  "method": "string (required)",
  "endpoint": "string (required)", 
  "status_code": "integer (required)",
  "timestamp": "string (required)",
  "request_size": "integer (optional, default: 0)",
  "response_size": "integer (optional, default: 0)",
  "response_time_ms": "float (optional, default: 0.0)",
  "query_length": "integer (optional, default: 0)",
  "query_data": "string (optional, default: \"\")"
}
```

### Field Descriptions
- **ip** (required): Client IP address
- **method** (required): HTTP method (GET, POST, PUT, DELETE, etc.)
- **endpoint** (required): URL path (e.g., "/about", "/api/contact")
- **status_code** (required): HTTP response status code (e.g., 200, 404, 500)
- **timestamp** (required): ISO-8601 timestamp (e.g., "2024-09-05T10:30:00Z")
- **request_size** (optional): Request size in bytes
- **response_size** (optional): Response size in bytes  
- **response_time_ms** (optional): Response time in milliseconds
- **query_length** (optional): Query string length
- **query_data** (optional): Query string data (truncated to 2000 chars)

## Example Request
```json
{
  "ip": "192.168.1.100",
  "method": "GET",
  "endpoint": "/about",
  "status_code": 200,
  "timestamp": "2024-09-05T10:30:00Z",
  "request_size": 1024,
  "response_size": 2048,
  "response_time_ms": 150.5,
  "query_length": 0,
  "query_data": ""
}
```

## Example Response
```json
{
  "success": true,
  "message": "Traffic ingested successfully",
  "session_id": "d261bfc44942465f8a5f3312734be21e",
  "request_count": 1
}
```

## Required Headers
- `Content-Type: application/json`

## CORS Configuration
✅ **Confirmed:** `https://singhaman.me` is added to the allowed origins in the CORS configuration.

## Security Pipeline
The ingested traffic automatically goes through the existing Sentinel pipeline:

1. **Request Logging** - Traffic is stored in the `request_logs` table
2. **Session Building** - Requests are grouped by IP into sessions (30-minute timeout)
3. **Behavior Feature Extraction** - 28 behavior features are extracted every 5 requests
4. **Behavior Model** - RandomForest model predicts if session is attacker/normal
5. **Behavior Agent** - Deterministic decision: BLOCK for attacker, ALLOW for normal
6. **Alert/Blocking** - IPs are automatically blocked if classified as malicious

## Integration Flow
```
User → singhaman.me → traffic capture → POST /api/ingest-traffic → 
Sentinel RequestLog → Session Builder → Behavior ML → Agent → 
Alert/Block → Sentinel Dashboard
```

## Authentication
No authentication required for this endpoint. The system relies on IP-based analysis and behavior patterns.

## Error Handling
The endpoint returns appropriate error responses:
- `400`: Invalid request data
- `500`: Server error during processing

Example error response:
```json
{
  "success": false,
  "message": "Failed to ingest traffic: <error details>"
}
```

## Important Notes
- The system respects the existing `SESSION_EVAL_THRESHOLD` (5 requests) for behavior evaluation
- Blocking duration is set to 60 minutes by default
- All existing middleware (RequestLoggingMiddleware, IPBlockMiddleware) remain unchanged
- The new endpoint complements the existing `/analyze` and `/predict` endpoints

## Deployment Status
✅ Changes have been committed and pushed to the `pre-deployment` branch
✅ Render configuration updated with CORS origins
✅ The deployment should be automatic via the connected render.yaml

## Next Steps
1. Monitor the Render dashboard for deployment completion
2. Test the production endpoint with sample traffic data
3. Implement the traffic capture logic on singhaman.me
4. Monitor the Sentinel dashboard for incoming traffic and security alerts