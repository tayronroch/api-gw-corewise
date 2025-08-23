"""
Middleware do Core - Sistema Global de Auditoria
"""
# Import audit middleware
from .audit_middleware import *

import uuid
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser
from django.urls import resolve
from .audit_models import AuditEvent


class CorrelationIdMiddleware(MiddlewareMixin):
    """Gera/propaga X-Correlation-Id em request/response."""

    request_header_key = 'HTTP_X_CORRELATION_ID'
    response_header_key = 'X-Correlation-Id'

    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)

    def process_request(self, request):
        correlation_id = request.META.get(self.request_header_key)
        if not correlation_id:
            correlation_id = uuid.uuid4().hex
        request.correlation_id = correlation_id

    def process_response(self, request, response):
        correlation_id = getattr(request, 'correlation_id', None)
        if correlation_id:
            response[self.response_header_key] = correlation_id
        return response


class AuditMiddleware(MiddlewareMixin):
    """Registra API_CALL em /api/* (exceto health/metrics/schema)."""

    IGNORE_PREFIXES = ['/static/', '/media/']
    IGNORE_CONTAINS = ['/health', '/metrics', '/schema']

    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)

    def process_response(self, request, response):
        try:
            path = getattr(request, 'path', '') or ''
            if not path.startswith('/api/'):
                return response
            if any(pref in path for pref in self.IGNORE_CONTAINS):
                return response
            if any(path.startswith(p) for p in self.IGNORE_PREFIXES):
                return response

            user = None
            if hasattr(request, 'user') and not isinstance(request.user, AnonymousUser):
                user = request.user

            method = getattr(request, 'method', '') or ''
            status_code = getattr(response, 'status_code', 0) or 0
            success = 200 <= int(status_code) < 400
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            ip = self._get_client_ip(request)
            correlation_id = getattr(request, 'correlation_id', '') or ''

            # Resolver info (opcional)
            metadata = {}
            try:
                match = resolve(path)
                if match:
                    metadata['view_name'] = getattr(match, 'view_name', '') or ''
                    metadata['url_name'] = getattr(match, 'url_name', '') or ''
                    metadata['app_name'] = getattr(match, 'app_name', '') or ''
            except Exception:
                pass

            AuditEvent.objects.create(
                user=user,
                action='API_CALL',
                ip=ip,
                user_agent=user_agent,
                path=path,
                method=method,
                status_code=status_code,
                success=success,
                metadata=metadata,
                correlation_id=correlation_id,
            )
        except Exception:
            # Nunca quebrar a resposta por erro de auditoria
            pass
        return response

    @staticmethod
    def _get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')