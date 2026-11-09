import time
from collections import defaultdict
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import get_settings

class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.requests = defaultdict(list)
        self.settings = get_settings()

    async def dispatch(self, request: Request, call_next):
        # Only rate limit scan creation
        if request.url.path.endswith("/api/scans") and request.method == "POST":
            session_id = request.headers.get("X-Session-Id", request.client.host if request.client else "unknown")
            now = time.time()
            one_hour_ago = now - 3600

            # Clean old records
            self.requests[session_id] = [ts for ts in self.requests[session_id] if ts > one_hour_ago]

            if len(self.requests[session_id]) >= self.settings.MAX_SCANS_PER_HOUR:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Maximum {self.settings.MAX_SCANS_PER_HOUR} scans per hour."
                )

            self.requests[session_id].append(now)

        return await call_next(request)
