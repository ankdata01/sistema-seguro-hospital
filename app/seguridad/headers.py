"""Cabeceras HTTP de endurecimiento para respuestas dinámicas y estáticas."""
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import HTTPS_ONLY

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
        if not request.url.path.startswith("/estaticos/"):
            response.headers.setdefault("Cache-Control", "no-store"); response.headers.setdefault("Pragma", "no-cache")
        if HTTPS_ONLY: response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response
