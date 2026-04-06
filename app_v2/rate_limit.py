from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app_v2.config import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.window_seconds = 60
        self.hits: Dict[str, Deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        now = time.time()
        queue = self.hits[client]
        while queue and now - queue[0] > self.window_seconds:
            queue.popleft()
        if len(queue) >= settings.rate_limit_per_minute:
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
        queue.append(now)
        return await call_next(request)
