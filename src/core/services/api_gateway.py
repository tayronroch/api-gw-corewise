"""API Gateway do Core

Encaminha requisições para os microsserviços registrados no ServiceRegistry.
Suporta proxy básico por nome do serviço e caminho relativo.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

import requests
from django.http import HttpRequest, JsonResponse, HttpResponse

from .service_registry import service_registry

logger = logging.getLogger(__name__)


class APIGateway:
    """Gateway simples para proxy de requisições entre serviços."""

    def __init__(self, default_timeout: int = 30) -> None:
        self.default_timeout = default_timeout

    def proxy(
        self,
        request: HttpRequest,
        service_name: str,
        target_path: str,
    ) -> HttpResponse:
        """Encaminha a requisição ao serviço indicado."""
        service = service_registry.get_service(service_name)
        if service is None:
            return JsonResponse({"error": f"service '{service_name}' not found"}, status=404)

        # Monta URL de destino
        base = service.base_url.rstrip("/")
        rel = target_path.lstrip("/")
        url = f"{base}/{rel}"

        headers = self._forward_headers(request)
        method = request.method.upper()
        params = request.GET.dict()
        data: Optional[bytes] = request.body if method in {"POST", "PUT", "PATCH"} else None

        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                timeout=self.default_timeout,
            )

            content_type = resp.headers.get("Content-Type", "application/json")
            status_code = resp.status_code

            # Tenta retornar JSON quando apropriado
            if "application/json" in content_type:
                try:
                    payload = resp.json()
                except ValueError:
                    payload = {"raw": resp.text}
                return JsonResponse(payload, status=status_code, safe=False)

            # Conteúdo não JSON
            response = HttpResponse(content=resp.content, status=status_code)
            response["Content-Type"] = content_type
            return response

        except requests.RequestException as exc:
            logger.error("Gateway proxy error to %s: %s", url, exc)
            return JsonResponse({"error": "gateway_error", "detail": str(exc)}, status=502)

    def _forward_headers(self, request: HttpRequest) -> Dict[str, str]:
        """Seleciona e encaminha headers relevantes para o serviço de destino."""
        copy = {}
        for key in [
            "Authorization",
            "Content-Type",
            "Accept",
            "User-Agent",
            "X-Request-ID",
        ]:
            if key in request.headers:
                copy[key] = request.headers[key]
        copy["X-Forwarded-For"] = request.META.get("REMOTE_ADDR", "")
        copy["X-Gateway"] = "CoreWise-API-Gateway"
        return copy


# Instância reutilizável
api_gateway = APIGateway()


