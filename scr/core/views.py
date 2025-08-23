"""
Views do Core - Auditoria global e API Gateway
"""

# Importa as views de auditoria existentes
from .audit_views import *  # noqa: F401,F403

from django.http import JsonResponse, HttpRequest
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from .services.api_gateway import api_gateway
from .services.service_registry import service_registry


@method_decorator(csrf_exempt, name="dispatch")
class ProxyView(View):
    """View genérica de proxy via API Gateway.

    Uso: /api/core/proxy/<service>/<path>
    """

    def dispatch(self, request: HttpRequest, service: str, path: str, *args, **kwargs):
        return api_gateway.proxy(request, service, path)


@method_decorator(csrf_exempt, name="dispatch")
class ServiceRegistryView(View):
    """Endpoints para listar e registrar microsserviços."""

    def get(self, request: HttpRequest):
        services = service_registry.get_all_active_services()
        payload = [
            {
                "id": str(s.id),
                "name": s.name,
                "type": s.service_type,
                "version": s.version,
                "base_url": s.base_url,
                "status": s.status,
                "last_health_check": s.last_health_check.isoformat() if s.last_health_check else None,
                "response_time_ms": s.response_time_ms,
            }
            for s in services
        ]
        return JsonResponse({"services": payload, "total": len(payload)})

    def post(self, request: HttpRequest):
        # aceita JSON ou form-encoded
        data = {}
        if request.body:
            try:
                import json as _json

                data = _json.loads(request.body.decode("utf-8"))
            except Exception:
                data = request.POST.dict()
        else:
            data = request.POST.dict()

        required = ["name", "service_type", "base_url", "health_check_url"]
        missing = [k for k in required if not data.get(k)]
        if missing:
            return JsonResponse({"error": "missing_fields", "fields": missing}, status=400)

        svc = service_registry.register_service(
            name=data["name"],
            service_type=data["service_type"],
            base_url=data["base_url"],
            health_check_url=data["health_check_url"],
            version=data.get("version", "1.0.0"),
        )
        return JsonResponse({"message": "registered", "id": str(svc.id)}, status=201)


class ServiceHealthView(View):
    """Retorna visão consolidada de saúde dos serviços."""

    def get(self, request: HttpRequest):
        services = service_registry.get_all_active_services()
        total = len(services)
        ok = sum(1 for s in services if s.status == "active")
        details = {
            s.name: {
                "status": s.status,
                "response_time_ms": s.response_time_ms,
                "last": s.last_health_check.isoformat() if s.last_health_check else None,
            }
            for s in services
        }
        overall = (ok / total * 100) if total else 0
        return JsonResponse({
            "overall_health": overall,
            "total_services": total,
            "healthy_services": ok,
            "services": details,
        })
