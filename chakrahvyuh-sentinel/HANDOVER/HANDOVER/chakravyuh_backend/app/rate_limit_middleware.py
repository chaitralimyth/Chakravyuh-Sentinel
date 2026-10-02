"""
Rate limiting middleware using sliding window algorithm.

Implements per-IP rate limiting with configurable time windows and burst capacity.
Uses in-memory tracking for efficiency with automatic cleanup of old entries.
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, Deque, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from fastapi import Request

from app.config import (
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_BURST,
    RATE_LIMIT_EXEMPT_PATHS
)
from app.database import SessionLocal
from app.db_models import RateLimitEvent


class RateLimiter:
    """
    Thread-safe rate limiter using sliding window algorithm.
    
    Tracks request timestamps per IP and enforces rate limits with burst tolerance.
    Automatically cleans up old entries to prevent memory leaks.
    """
    
    def __init__(self, max_requests: int, window_seconds: int, burst: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.burst = burst
        # Store request timestamps per IP: {ip: deque([timestamp1, timestamp2, ...])}
        self.request_history: Dict[str, Deque[float]] = defaultdict(deque)
        # Track when each IP was last cleaned up
        self.last_cleanup: Dict[str, float] = {}
        
    def is_allowed(self, ip: str) -> Tuple[bool, Dict[str, int]]:
        """
        Check if request from IP is allowed under rate limit.
        
        Returns:
            tuple: (is_allowed, rate_limit_info)
                is_allowed: True if request is within limits
                rate_limit_info: Dict with current rate limit stats
        """
        current_time = time.time()
        
        # Clean up old requests for this IP
        self._cleanup_old_requests(ip, current_time)
        
        # Get current request count
        request_count = len(self.request_history[ip])
        
        # Calculate time since oldest request in window
        time_in_window = 0
        if request_count > 0:
            oldest_request = self.request_history[ip][0]
            time_in_window = current_time - oldest_request
        
        # Check if within normal rate limit
        if request_count < self.max_requests:
            self.request_history[ip].append(current_time)
            return True, {
                "limit": self.max_requests,
                "remaining": self.max_requests - request_count - 1,
                "reset": int(oldest_request + self.window_seconds) if request_count > 0 else int(current_time + self.window_seconds),
                "window": self.window_seconds,
                "current": request_count + 1
            }
        
        # Check burst capacity (allow short bursts above normal rate)
        if request_count < self.max_requests + self.burst:
            # Only allow burst if we're in the first half of the time window
            # This prevents sustained abuse of burst capacity
            if time_in_window < self.window_seconds * 0.5:
                self.request_history[ip].append(current_time)
                return True, {
                    "limit": self.max_requests + self.burst,
                    "remaining": self.max_requests + self.burst - request_count - 1,
                    "reset": int(oldest_request + self.window_seconds),
                    "window": self.window_seconds,
                    "current": request_count + 1,
                    "burst_used": True
                }
        
        # Rate limit exceeded
        return False, {
            "limit": self.max_requests,
            "remaining": 0,
            "reset": int(oldest_request + self.window_seconds),
            "window": self.window_seconds,
            "current": request_count
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
        current_time = time.time()
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
    burst=RATE_LIMIT_BURST
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware for FastAPI.
    
    Enforces per-IP rate limits on all requests except exempt paths.
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
        path = request.url.path
        
        # Skip rate limiting for exempt paths
        if path in RATE_LIMIT_EXEMPT_PATHS or path.startswith(("/docs", "/redoc", "/openapi")):
            return await call_next(request)
        
        client_ip = request.client.host if request.client else "unknown"
        
        # Skip rate limiting for localhost during development
        if client_ip in ["127.0.0.1", "localhost", "::1"]:
            return await call_next(request)
        
        # Check rate limit
        is_allowed, rate_info = _rate_limiter.is_allowed(client_ip)
        
        # Add rate limit headers to response
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(rate_info["limit"])
        response.headers["X-RateLimit-Remaining"] = str(rate_info["remaining"])
        response.headers["X-RateLimit-Reset"] = str(rate_info["reset"])
        response.headers["X-RateLimit-Window"] = str(rate_info["window"])
        
        if not is_allowed:
            # Log rate limit violation to database
            self._log_rate_limit_violation(client_ip, request, rate_info)
            
            return JSONResponse(
                {
                    "detail": "Rate limit exceeded",
                    "rate_limit": rate_info,
                    "retry_after": rate_info["reset"] - int(time.time())
                },
                status_code=429,
                headers={
                    "X-RateLimit-Limit": str(rate_info["limit"]),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(rate_info["reset"]),
                    "X-RateLimit-Window": str(rate_info["window"]),
                    "Retry-After": str(rate_info["reset"] - int(time.time()))
                }
            )
        
        return response


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    return _rate_limiter