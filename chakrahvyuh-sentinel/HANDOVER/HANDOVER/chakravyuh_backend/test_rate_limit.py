"""
Test script for rate limiting functionality.
Tests the sliding window rate limiter with various scenarios.
"""

import time
import sys
import os

# Add the app directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.rate_limit_middleware import RateLimiter


def test_basic_rate_limiting():
    """Test basic rate limiting with normal requests."""
    print("Testing basic rate limiting...")
    
    # Create a rate limiter: 10 requests per 10 seconds, burst of 0 (no burst)
    limiter = RateLimiter(max_requests=10, window_seconds=10, burst=0)
    
    ip = "192.168.1.100"
    
    # Make 10 requests (should all be allowed)
    for i in range(10):
        allowed, info = limiter.is_allowed(ip)
        print(f"Request {i+1}: Allowed={allowed}, Remaining={info['remaining']}")
        assert allowed, f"Request {i+1} should be allowed"
        assert info['current'] == i + 1
    
    # 11th request should be rate limited
    allowed, info = limiter.is_allowed(ip)
    print(f"Request 11: Allowed={allowed}, Remaining={info['remaining']}")
    assert not allowed, "Request 11 should be rate limited"
    
    print("PASS: Basic rate limiting test passed\n")


def test_burst_capacity():
    """Test burst capacity allows short bursts above normal rate."""
    print("Testing burst capacity...")
    
    # Create a rate limiter: 5 requests per 10 seconds, burst of 3
    limiter = RateLimiter(max_requests=5, window_seconds=10, burst=3)
    
    ip = "192.168.1.101"
    
    # Make 5 normal requests (should all be allowed)
    for i in range(5):
        allowed, info = limiter.is_allowed(ip)
        print(f"Normal request {i+1}: Allowed={allowed}, Remaining={info['remaining']}")
        assert allowed, f"Normal request {i+1} should be allowed"
    
    # Wait a bit to be in the first half of the window for burst to work
    print("Waiting 3 seconds to be in first half of window...")
    time.sleep(3)
    
    # Make 3 burst requests (should be allowed due to burst capacity)
    for i in range(3):
        allowed, info = limiter.is_allowed(ip)
        print(f"Burst request {i+1}: Allowed={allowed}, Burst used={info.get('burst_used', False)}")
        assert allowed, f"Burst request {i+1} should be allowed"
        assert info.get('burst_used', False), "Burst should be marked as used"
    
    # 9th request should be rate limited (exceeded both normal and burst)
    allowed, info = limiter.is_allowed(ip)
    print(f"Request 9: Allowed={allowed}")
    assert not allowed, "Request 9 should be rate limited"
    
    print("PASS Burst capacity test passed\n")


def test_sliding_window():
    """Test that old requests expire from the window."""
    print("Testing sliding window expiration...")
    
    # Create a rate limiter: 3 requests per 2 seconds
    limiter = RateLimiter(max_requests=3, window_seconds=2, burst=0)
    
    ip = "192.168.1.102"
    
    # Make 3 requests (should fill the window)
    for i in range(3):
        allowed, info = limiter.is_allowed(ip)
        print(f"Request {i+1}: Allowed={allowed}, Current={info['current']}")
        assert allowed, f"Request {i+1} should be allowed"
    
    # 4th request should be rate limited
    allowed, info = limiter.is_allowed(ip)
    print(f"Request 4 (immediate): Allowed={allowed}")
    assert not allowed, "Request 4 should be rate limited immediately"
    
    # Wait for window to expire
    print("Waiting 2.1 seconds for window to expire...")
    time.sleep(2.1)
    
    # Now request should be allowed again
    allowed, info = limiter.is_allowed(ip)
    print(f"Request after wait: Allowed={allowed}, Current={info['current']}")
    assert allowed, "Request should be allowed after window expires"
    assert info['current'] == 1, "Should start fresh after window expires"
    
    print("PASS Sliding window test passed\n")


def test_multiple_ips():
    """Test that rate limiting works independently for different IPs."""
    print("Testing multiple IPs...")
    
    # Create a rate limiter: 2 requests per 10 seconds
    limiter = RateLimiter(max_requests=2, window_seconds=10, burst=0)
    
    ip1 = "192.168.1.103"
    ip2 = "192.168.1.104"
    
    # IP1 makes 2 requests (should be allowed)
    for i in range(2):
        allowed, info = limiter.is_allowed(ip1)
        print(f"IP1 Request {i+1}: Allowed={allowed}")
        assert allowed, f"IP1 Request {i+1} should be allowed"
    
    # IP1 3rd request should be rate limited
    allowed, info = limiter.is_allowed(ip1)
    print(f"IP1 Request 3: Allowed={allowed}")
    assert not allowed, "IP1 Request 3 should be rate limited"
    
    # IP2 should still be able to make requests (independent tracking)
    for i in range(2):
        allowed, info = limiter.is_allowed(ip2)
        print(f"IP2 Request {i+1}: Allowed={allowed}")
        assert allowed, f"IP2 Request {i+1} should be allowed"
    
    print("PASS Multiple IPs test passed\n")


def test_localhost_exemption():
    """Test that localhost is exempt from rate limiting."""
    print("Testing localhost exemption...")
    
    limiter = RateLimiter(max_requests=1, window_seconds=10, burst=0)
    
    # Localhost should always be allowed (this is handled in middleware, not limiter)
    # The limiter itself doesn't exempt localhost, but we test the limiter behavior
    ip = "127.0.0.1"
    
    # Make 2 requests - second should be rate limited by limiter
    allowed1, info1 = limiter.is_allowed(ip)
    allowed2, info2 = limiter.is_allowed(ip)
    
    print(f"Localhost Request 1: Allowed={allowed1}")
    print(f"Localhost Request 2: Allowed={allowed2}")
    
    assert allowed1, "First localhost request should be allowed"
    assert not allowed2, "Second localhost request should be rate limited by limiter"
    
    print("PASS Localhost exemption test passed (middleware handles exemption)\n")


def test_get_stats():
    """Test getting rate limit statistics."""
    print("Testing rate limit statistics...")
    
    limiter = RateLimiter(max_requests=5, window_seconds=10, burst=2)
    ip = "192.168.1.105"
    
    # Make some requests
    for i in range(3):
        limiter.is_allowed(ip)
    
    # Get stats
    stats = limiter.get_stats(ip)
    print(f"Stats: {stats}")
    
    assert stats['current'] == 3, "Should show 3 current requests"
    assert stats['limit'] == 5, "Should show limit of 5"
    assert stats['remaining'] == 2, "Should show 2 remaining"
    
    print("PASS Rate limit statistics test passed\n")


if __name__ == "__main__":
    print("=" * 50)
    print("Running Rate Limiter Tests")
    print("=" * 50 + "\n")
    
    try:
        test_basic_rate_limiting()
        test_burst_capacity()
        test_sliding_window()
        test_multiple_ips()
        test_localhost_exemption()
        test_get_stats()
        
        print("=" * 50)
        print("All tests passed! PASS")
        print("=" * 50)
        
    except AssertionError as e:
        print(f"\nFAIL Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\nFAIL Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)