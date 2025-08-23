"""Serviços centrais do módulo Core.

Inclui registro de microsserviços, API gateway, balanceamento
e utilitários de infraestrutura.
"""

from .service_registry import ServiceRegistry, service_registry  # noqa: F401

__all__ = [
    "ServiceRegistry",
    "service_registry",
]


