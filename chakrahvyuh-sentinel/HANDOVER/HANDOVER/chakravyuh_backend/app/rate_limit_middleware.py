"""
Rate limiting middleware using sliding window algorithm.

Implements per-IP rate limiting with configurable time windows and burst capacity.
Uses in-memory tracking for efficiency with automatic cleanup of old entries.
"""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, Deque, Tuple, Optional, Any, Set

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from fastapi import Request

from app.config import (
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_MODERATE_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_BURST,
    RATE_LIMIT_EXEMPT_PATHS
)
from app.database import SessionLocal
from app.db_models import RateLimitEvent, SecurityAlert
from app.ip_service import get_client_ip


class RateLimiter:
    """
    Thread-safe rate limiter using sliding window algorithm.
    
    Tracks request timestamps per IP and enforces rate limits with burst tolerance.
    Supports dynamic rate limiting for moderate-risk clients (score 59-79).
    Synchronizes with authoritative database RequestLogs across server restarts.
    Automatically cleans up old entries to prevent memory leaks.
    """
    
    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        burst: int,
        moderate_requests: int = RATE_LIMIT_MODERATE_REQUESTS,
        sync_db: bool = False,
    ):
        self._lock = threading.Lock()
        self.max_requests = max_requests
        self.moderate_requests = moderate_requests
        self.window_seconds = window_seconds
        self.burst = burst
        self.sync_db = sync_db
        # Store request timestamps per IP: {ip: deque([timestamp1, timestamp2, ...])}
        self.request_history: Dict[str, Deque[float]] = defaultdict(deque)
        # Track when each IP was last cleaned up
        self.last_cleanup: Dict[str, float] = {}
        # Dynamic risk score cache per IP: {ip: (risk_score, updated_timestamp)}
        self.ip_risk_scores: Dict[str, Tuple[float, float]] = {}
        # Track IPs whose DB history has been synchronized
        self._synced_ips: Set[str] = set()

    def _sync_from_db(self, ip: str, current_time: float):
        """Restore recent requests from RequestLog database into sliding window state."""
        if not self.sync_db or ip in self._synced_ips:
            return
        self._synced_ips.add(ip)
        try:
            from app.db_models import RequestLog
            cutoff_dt = datetime.now(timezone.utc) - timedelta(seconds=self.window_seconds)
            db = SessionLocal()
            try:
                rows = (
                    db.query(RequestLog.timestamp)
                    .filter(RequestLog.ip == ip, RequestLog.timestamp >= cutoff_dt)
                    .order_by(RequestLog.timestamp.asc())
                    .all()
                )
                existing_timestamps = set(self.request_history[ip])
                for (ts,) in rows:
                    if ts is not None:
                        epoch = ts.timestamp() if ts.tzinfo else ts.replace(tzinfo=timezone.utc).timestamp()
                        if epoch >= current_time - self.window_seconds and epoch not in existing_timestamps:
                            self.request_history[ip].append(epoch)
                            existing_timestamps.add(epoch)
                if self.request_history[ip]:
                    self.request_history[ip] = deque(sorted(self.request_history[ip]))
            finally:
                db.close()
        except Exception:
            pass

    def reset_ip(self, ip: str):
        """Clear rate limit tracking history and risk scores for an IP."""
        with self._lock:
            if ip in self.request_history:
                del self.request_history[ip]
            if ip in self.last_cleanup:
                del self.last_cleanup[ip]
            # Keep marked as synced so prior historical DB rows are not reloaded on reset
            self._synced_ips.add(ip)

    def set_ip_risk(self, ip: str, risk_score: float, force: bool = False):
        """Record the active risk score for an IP. Retains highest elevated risk in window unless forced."""
        with self._lock:
            existing = self.get_ip_risk(ip)
            if not force and existing is not None and existing > float(risk_score):
                return
            self.ip_risk_scores[ip] = (float(risk_score), time.time())

    def get_ip_risk(self, ip: str) -> Optional[float]:
        """Get the active risk score for an IP within the 30-minute session window."""
        entry = self.ip_risk_scores.get(ip)
        if entry:
            score, ts = entry
            if time.time() - ts < 1800:
                return score
        return None

    def is_moderate_risk(self, ip: str) -> bool:
        """Check if an IP is currently evaluated in the moderate-risk range (59.0 < score <= 79.0)."""
        score = self.get_ip_risk(ip)
        return score is not None and (59.0 < score <= 79.0)

    def is_allowed(self, ip: str, is_moderate_risk: Optional[bool] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request from IP is allowed under rate limit.
        Applies moderate-risk strict quota if IP is flagged in 59-79 score tier.
        
        Returns:
            tuple: (is_allowed, rate_limit_info)
        """
        with self._lock:
            current_time = time.time()
            self._sync_from_db(ip, current_time)
            self._cleanup_old_requests(ip, current_time)
            request_count = len(self.request_history[ip])

            if is_moderate_risk is None:
                is_moderate_risk = self.is_moderate_risk(ip)

            effective_limit = self.moderate_requests if is_moderate_risk else self.max_requests
            effective_burst = 0 if is_moderate_risk else self.burst

            time_in_window = 0
            if request_count > 0:
                oldest_request = self.request_history[ip][0]
                time_in_window = current_time - oldest_request
            else:
                oldest_request = current_time

            reset_time = int(oldest_request + self.window_seconds)

            if request_count < effective_limit:
                self.request_history[ip].append(current_time)
                return True, {
                    "limit": effective_limit,
                    "remaining": effective_limit - request_count - 1,
                    "reset": reset_time,
                    "window": self.window_seconds,
                    "current": request_count + 1,
                    "tier": "MODERATE_RISK" if is_moderate_risk else "STANDARD",
                }

            # Burst capacity only for standard/normal tier
            if not is_moderate_risk and request_count < effective_limit + effective_burst:
                if time_in_window < self.window_seconds * 0.5:
                    self.request_history[ip].append(current_time)
                    return True, {
                        "limit": effective_limit + effective_burst,
                        "remaining": effective_limit + effective_burst - request_count - 1,
                        "reset": reset_time,
                        "window": self.window_seconds,
                        "current": request_count + 1,
                        "burst_used": True,
                        "tier": "STANDARD",
                    }

            # Rate limit exceeded
            return False, {
                "limit": effective_limit,
                "remaining": 0,
                "reset": reset_time,
                "window": self.window_seconds,
                "current": request_count,
                "tier": "MODERATE_RISK" if is_moderate_risk else "STANDARD",
            }

    def check_allowed(self, ip: str, is_moderate_risk: Optional[bool] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Non-mutating rate limit check: inspects if request from IP is currently allowed
        WITHOUT recording a request timestamp or modifying sliding-window history.
        """
        with self._lock:
            current_time = time.time()
            self._sync_from_db(ip, current_time)
            self._cleanup_old_requests(ip, current_time)
            request_count = len(self.request_history[ip])

            if is_moderate_risk is None:
                is_moderate_risk = self.is_moderate_risk(ip)

            effective_limit = self.moderate_requests if is_moderate_risk else self.max_requests
            effective_burst = 0 if is_moderate_risk else self.burst

            time_in_window = 0
            if request_count > 0:
                oldest_request = self.request_history[ip][0]
                time_in_window = current_time - oldest_request
            else:
                oldest_request = current_time

            reset_time = int(oldest_request + self.window_seconds)

            if request_count < effective_limit:
                return True, {
                    "limit": effective_limit,
                    "remaining": effective_limit - request_count,
                    "reset": reset_time,
                    "window": self.window_seconds,
                    "current": request_count,
                    "tier": "MODERATE_RISK" if is_moderate_risk else "STANDARD",
                }

            if not is_moderate_risk and request_count < effective_limit + effective_burst:
                if time_in_window < self.window_seconds * 0.5:
                    return True, {
                        "limit": effective_limit + effective_burst,
                        "remaining": effective_limit + effective_burst - request_count,
                        "reset": reset_time,
                        "window": self.window_seconds,
                        "current": request_count,
                        "burst_used": True,
                        "tier": "STANDARD",
                    }

            return False, {
                "limit": effective_limit,
                "remaining": 0,
                "reset": reset_time,
                "window": self.window_seconds,
                "current": request_count,
                "tier": "MODERATE_RISK" if is_moderate_risk else "STANDARD",
            }
    
    def _cleanup_old_requests(self, ip: str, current_time: float):
        """Remove requests older than the time window."""
        cutoff_time = current_time - self.window_seconds
        
        # Remove old timestamps from the front of the deque
        while self.request_history[ip] and self.request_history[ip][0] < cutoff_time:
            self.request_history[ip].popleft()
        
        # Clean up empty entries periodically
        if not self.request_history[ip] and ip in self.last_cleanup:
            # Only remove if cleaned up recently (prevent thrashing)
            if current_time - self.last_cleanup[ip] > self.window_seconds * 2:
                del self.request_history[ip]
                del self.last_cleanup[ip]
        else:
            self.last_cleanup[ip] = current_time
    
    def get_stats(self, ip: str) -> Dict[str, int]:
        """Get current rate limit statistics for an IP."""
        with self._lock:
            current_time = time.time()
            self._sync_from_db(ip, current_time)
            self._cleanup_old_requests(ip, current_time)

            request_count = len(self.request_history[ip])
            oldest_request = self.request_history[ip][0] if request_count > 0 else current_time

            return {
                "current": request_count,
                "limit": self.max_requests,
                "remaining": max(0, self.max_requests - request_count),
                "reset": int(oldest_request + self.window_seconds),
                "window": self.window_seconds
            }


# Global rate limiter instance
_rate_limiter = RateLimiter(
    max_requests=RATE_LIMIT_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
    burst=RATE_LIMIT_BURST,
    moderate_requests=RATE_LIMIT_MODERATE_REQUESTS,
    sync_db=True,
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware for FastAPI.
    
    Enforces per-IP rate limits on all requests except exempt paths.
    Enforces strict rate limiting on moderate-risk clients (score 59-79).
    Returns 429 Too Many Requests when rate limit is exceeded.
    """
    
    def _log_rate_limit_violation(self, ip: str, request: Request, rate_info: Dict):
        """Log rate limit violation to database for monitoring."""
        try:
            db = SessionLocal()
            try:
                violation = RateLimitEvent(
                    ip=ip,
                    endpoint=request.url.path,
                    method=request.method,
                    request_count=rate_info["current"],
                    window_seconds=rate_info["window"],
                    limit=rate_info["limit"],
                    burst_used=rate_info.get("burst_used", False)
                )
                db.add(violation)
                db.commit()
            finally:
                db.close()
        except Exception as e:
            # Don't fail the request if logging fails
            print(f"Failed to log rate limit violation: {e}")
    
    async def dispatch(self, request: Request, call_next):
        # Always allow CORS preflight requests
        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path
        
        # Skip rate limiting for exempt paths
        if path in RATE_LIMIT_EXEMPT_PATHS or path.startswith(("/docs", "/redoc", "/openapi", "/api/check-ip")):
            return await call_next(request)
        
        client_ip = get_client_ip(request)

        # Check if client has moderate risk (score 59-79)
        is_moderate = _rate_limiter.is_moderate_risk(client_ip)
        if not is_moderate and _rate_limiter.get_ip_risk(client_ip) is None:
            try:
                db = SessionLocal()
                try:
                    alert = (
                        db.query(SecurityAlert)
                        .filter(SecurityAlert.ip == client_ip)
                        .order_by(SecurityAlert.created_at.desc())
                        .first()
                    )
                    if alert and alert.risk_score:
                        _rate_limiter.set_ip_risk(client_ip, alert.risk_score)
                        is_moderate = _rate_limiter.is_moderate_risk(client_ip)
                finally:
                    db.close()
            except Exception:
                pass
        
        # Check rate limit (standard or moderate-risk tier)
        is_allowed, rate_info = _rate_limiter.is_allowed(client_ip, is_moderate_risk=is_moderate)
        
        if not is_allowed:
            # Log rate limit violation to database
            self._log_rate_limit_violation(client_ip, request, rate_info)
            
            retry_after = max(1, rate_info["reset"] - int(time.time()))
            detail_msg = (
                "Too Many Requests: Moderate-risk rate limit exceeded by Chakravyuh Sentinel"
                if is_moderate else "Rate limit exceeded"
            )
            return JSONResponse(
                {
                    "detail": detail_msg,
                    "rate_limit": rate_info,
                    "retry_after": retry_after
                },
                status_code=429,
                headers={
                    "X-RateLimit-Limit": str(rate_info["limit"]),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(rate_info["reset"]),
                    "X-RateLimit-Window": str(rate_info["window"]),
                    "Retry-After": str(retry_after)
                }
            )
        
        # Allowed: call downstream handler and attach rate limit headers
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(rate_info["limit"])
        response.headers["X-RateLimit-Remaining"] = str(rate_info["remaining"])
        response.headers["X-RateLimit-Reset"] = str(rate_info["reset"])
        response.headers["X-RateLimit-Window"] = str(rate_info["window"])

        return response


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    return _rate_limiter