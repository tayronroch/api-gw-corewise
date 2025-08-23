"""
Service Registry - Registro central de microsserviços do Core.

Responsável por:
- Registrar/atualizar serviços (nome, tipo, base_url, health)
- Listar serviços ativos por tipo
- Atualizar status/tempo de resposta (health checks externos)
- Obter endpoints por serviço
- Cache simples em memória para reduzir consultas
"""

from __future__ import annotations

import logging
from typing import List, Optional
from django.utils import timezone

from ..models import Microservice, ServiceEndpoint, CircuitBreaker

logger = logging.getLogger(__name__)


class ServiceRegistry:
    """Registro central de microsserviços."""

    def __init__(self) -> None:
        self._services_cache: dict[str, Microservice] = {}
        self._endpoints_cache: dict[str, List[ServiceEndpoint]] = {}
        self._last_cache_update: Optional[timezone.datetime] = None
        self._cache_ttl_seconds: int = 300  # 5 minutos

    # ---------------------- PUBLIC API ----------------------
    def register_service(
        self,
        name: str,
        service_type: str,
        base_url: str,
        health_check_url: str,
        version: str = "1.0.0",
    ) -> Microservice:
        """Registra ou atualiza um serviço por nome.

        Cria também um CircuitBreaker associado quando novo.
        """
        service, created = Microservice.objects.get_or_create(
            name=name,
            defaults={
                "service_type": service_type,
                "base_url": base_url,
                "health_check_url": health_check_url,
                "version": version,
                "status": "active",
            },
        )

        if created:
            logger.info("Novo microsserviço registrado: %s", name)
            CircuitBreaker.objects.create(service=service)
        else:
            # Atualiza dados principais
            service.service_type = service_type
            service.base_url = base_url
            service.health_check_url = health_check_url
            service.version = version
            service.save(update_fields=[
                "service_type", "base_url", "health_check_url", "version", "updated_at"
            ])
            logger.info("Microsserviço atualizado: %s", name)

        self._clear_cache()
        return service

    def get_service(self, name: str) -> Optional[Microservice]:
        """Obtém um serviço ativo por nome."""
        try:
            return Microservice.objects.get(name=name, is_public=True)
        except Microservice.DoesNotExist:
            return None

    def get_services_by_type(self, service_type: str) -> List[Microservice]:
        """Lista serviços ativos por tipo."""
        return list(
            Microservice.objects.filter(service_type=service_type, status="active")
        )

    def get_all_active_services(self) -> List[Microservice]:
        """Lista todos os serviços ativos."""
        return list(Microservice.objects.filter(status="active"))

    def update_service_status(self, name: str, status: str, response_time_ms: Optional[int] = None) -> None:
        """Atualiza status/health de um serviço."""
        try:
            service = Microservice.objects.get(name=name)
            service.status = status
            service.last_health_check = timezone.now()
            if response_time_ms is not None:
                service.response_time_ms = int(response_time_ms)
            service.save(update_fields=["status", "last_health_check", "response_time_ms", "updated_at"])
        except Microservice.DoesNotExist:
            logger.warning("Serviço %s não encontrado para atualização de status", name)

    def get_service_endpoints(self, service_name: str) -> List[ServiceEndpoint]:
        """Retorna endpoints ativos de um serviço."""
        try:
            service = Microservice.objects.get(name=service_name)
            return list(ServiceEndpoint.objects.filter(service=service, is_active=True))
        except Microservice.DoesNotExist:
            return []

    # ---------------------- INTERNAL ----------------------
    def _clear_cache(self) -> None:
        self._services_cache.clear()
        self._endpoints_cache.clear()
        self._last_cache_update = None


# Instância global do registro de serviços
service_registry = ServiceRegistry()


