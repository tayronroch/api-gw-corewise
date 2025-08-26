"""
Modelos principais do Core - Sistema Central de Microsserviços e Auditoria CoreWise
"""
from django.db import models
from django.utils import timezone
import uuid

# ==================== SERVICE REGISTRY MODELS ====================


class Microservice(models.Model):
    """Registro de microsserviços disponíveis no sistema"""

    SERVICE_TYPES = [
        ("mpls_analyzer", "MPLS Analyzer Service"),
        ("topology", "Topology Service"),
        ("networking", "Networking Service"),
        ("users", "Users Service"),
        ("engineering", "Engineering Service"),
        ("security", "Security Service"),
        ("dashboards", "Dashboards Service"),
    ]

    STATUS_CHOICES = [
        ("active", "Active"),
        ("inactive", "Inactive"),
        ("maintenance", "Maintenance"),
        ("error", "Error"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    service_type = models.CharField(max_length=50, choices=SERVICE_TYPES)
    version = models.CharField(max_length=20, default="1.0.0")
    base_url = models.URLField(max_length=500)
    health_check_url = models.URLField(max_length=500)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="active")
    last_health_check = models.DateTimeField(null=True, blank=True)
    response_time_ms = models.IntegerField(default=0)
    is_public = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "core_microservice"
        verbose_name = "Microservice"
        verbose_name_plural = "Microservices"
        ordering = ["name"]

    def __str__(self) -> str:  # pragma: no cover - representação simples
        return f"{self.name} ({self.get_service_type_display()}) - {self.status}"


class ServiceEndpoint(models.Model):
    """Endpoints disponíveis em cada microsserviço"""

    HTTP_METHODS = [
        ("GET", "GET"),
        ("POST", "POST"),
        ("PUT", "PUT"),
        ("PATCH", "PATCH"),
        ("DELETE", "DELETE"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service = models.ForeignKey(Microservice, on_delete=models.CASCADE, related_name="endpoints")
    path = models.CharField(max_length=200)
    method = models.CharField(max_length=10, choices=HTTP_METHODS)
    description = models.TextField(blank=True)
    requires_auth = models.BooleanField(default=True)
    rate_limit = models.IntegerField(default=10000)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "core_service_endpoint"
        verbose_name = "Service Endpoint"
        verbose_name_plural = "Service Endpoints"
        unique_together = ["service", "path", "method"]

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.service.name} {self.method} {self.path}"


# ==================== API GATEWAY MODELS ====================


class APIRoute(models.Model):
    """Configuração de rotas do API Gateway"""

    ROUTE_TYPES = [
        ("proxy", "Proxy Route"),
        ("aggregate", "Aggregate Route"),
        ("transform", "Transform Route"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    route_type = models.CharField(max_length=20, choices=ROUTE_TYPES, default="proxy")
    path_pattern = models.CharField(max_length=200, unique=True)
    target_service = models.ForeignKey(Microservice, on_delete=models.CASCADE, related_name="routes")
    target_path = models.CharField(max_length=200)
    http_method = models.CharField(max_length=10, choices=ServiceEndpoint.HTTP_METHODS)
    is_active = models.BooleanField(default=True)
    timeout_ms = models.IntegerField(default=30000)
    retry_count = models.IntegerField(default=3)
    circuit_breaker_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "core_api_route"
        verbose_name = "API Route"
        verbose_name_plural = "API Routes"
        ordering = ["path_pattern"]

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.name}: {self.path_pattern} → {self.target_service.name}"


class CircuitBreaker(models.Model):
    """Estado dos circuit breakers para cada serviço"""

    STATES = [
        ("closed", "Closed"),
        ("open", "Open"),
        ("half_open", "Half-Open"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service = models.OneToOneField(Microservice, on_delete=models.CASCADE, related_name="circuit_breaker")
    state = models.CharField(max_length=20, choices=STATES, default="closed")
    failure_count = models.IntegerField(default=0)
    threshold = models.IntegerField(default=5)
    last_failure = models.DateTimeField(null=True, blank=True)
    opened_at = models.DateTimeField(null=True, blank=True)
    timeout_seconds = models.IntegerField(default=60)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "core_circuit_breaker"
        verbose_name = "Circuit Breaker"
        verbose_name_plural = "Circuit Breakers"

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.service.name} - {self.state} (failures: {self.failure_count})"


# ==================== LOAD BALANCER MODELS ====================


class LoadBalancerConfig(models.Model):
    """Configuração do balanceador de carga"""

    ALGORITHMS = [
        ("round_robin", "Round Robin"),
        ("least_connections", "Least Connections"),
        ("weighted_round_robin", "Weighted Round Robin"),
        ("ip_hash", "IP Hash"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service = models.ForeignKey(Microservice, on_delete=models.CASCADE, related_name="load_balancer_configs")
    algorithm = models.CharField(max_length=30, choices=ALGORITHMS, default="round_robin")
    weight = models.IntegerField(default=1)
    max_connections = models.IntegerField(default=1000)
    health_check_interval = models.IntegerField(default=30)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "core_load_balancer_config"
        verbose_name = "Load Balancer Configuration"
        verbose_name_plural = "Load Balancer Configurations"

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.service.name} - {self.get_algorithm_display()} (weight: {self.weight})"


# ==================== METRICS & MONITORING MODELS ====================


class ServiceMetrics(models.Model):
    """Métricas de performance dos microsserviços"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    service = models.ForeignKey(Microservice, on_delete=models.CASCADE, related_name="metrics")
    timestamp = models.DateTimeField(default=timezone.now)
    response_time_ms = models.IntegerField()
    request_count = models.IntegerField(default=1)
    error_count = models.IntegerField(default=0)
    success_rate = models.FloatField(default=100.0)
    cpu_usage = models.FloatField(null=True, blank=True)
    memory_usage = models.FloatField(null=True, blank=True)

    class Meta:
        db_table = "core_service_metrics"
        verbose_name = "Service Metrics"
        verbose_name_plural = "Service Metrics"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["service", "timestamp"]),
            models.Index(fields=["timestamp"]),
        ]

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.service.name} - {self.timestamp} (RT: {self.response_time_ms}ms)"


# ==================== EXISTING AUDIT MODELS ====================

# Import all audit models to make them available in the core app
from .audit_models import (  # noqa: E402
    GlobalAccessLog,
    GlobalAuditLog,
    GlobalSecuritySettings,
    GlobalLoginAttempt,
    UserActivitySummary,
)

# Export all models for easy importing
__all__ = [
    # New Microservices Models
    "Microservice",
    "ServiceEndpoint",
    "APIRoute",
    "CircuitBreaker",
    "LoadBalancerConfig",
    "ServiceMetrics",
    # Existing Audit Models
    "GlobalAccessLog",
    "GlobalAuditLog",
    "GlobalSecuritySettings",
    "GlobalLoginAttempt",
    "UserActivitySummary",
]