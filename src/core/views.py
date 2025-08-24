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


# ============================
# Auth Views (JWT)
# ============================
import os
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.contrib.auth.models import User
from drf_spectacular.utils import extend_schema
try:
    from ratelimit.decorators import ratelimit
except Exception:  # fallback no-op se não instalado
    def ratelimit(*args, **kwargs):
        def _decorator(fn):
            return fn
        return _decorator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer
from .audit_models import AuditEvent


def _client_ip(request: HttpRequest) -> str:
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR') or ''


def _user_agent(request: HttpRequest) -> str:
    return request.META.get('HTTP_USER_AGENT', '')


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Registro de Usuário",
        description="Criação de nova conta de usuário no sistema",
        tags=['authentication'],
        responses={201: "Usuário criado com sucesso", 400: "Dados inválidos"}
    )
    def post(self, request: HttpRequest):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            AuditEvent.objects.create(
                user=user,
                action='REGISTER',
                ip=_client_ip(request),
                user_agent=_user_agent(request),
                path=request.path,
                method='POST',
                status_code=201,
                success=True,
                metadata={},
                correlation_id=getattr(request, 'correlation_id', ''),
            )
            return Response({'id': user.id, 'username': user.username, 'email': user.email}, status=status.HTTP_201_CREATED)
        AuditEvent.objects.create(
            user=None,
            action='REGISTER',
            ip=_client_ip(request),
            user_agent=_user_agent(request),
            path=request.path,
            method='POST',
            status_code=400,
            success=False,
            metadata={'errors': serializer.errors},
            correlation_id=getattr(request, 'correlation_id', ''),
        )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Login JWT",
        description="Autenticação de usuário e obtenção de tokens JWT",
        tags=['authentication'],
        responses={200: "Login bem-sucedido", 401: "Credenciais inválidas", 429: "Muitas tentativas"}
    )
    @ratelimit(key='ip', rate=os.environ.get('LOGIN_RATE_LIMIT', '5/m'), method='POST', block=False)
    def post(self, request: HttpRequest):
        # Rate limited?
        if getattr(request, 'limited', False):
            AuditEvent.objects.create(
                user=None,
                action='LOGIN_FAIL',
                ip=_client_ip(request),
                user_agent=_user_agent(request),
                path=request.path,
                method='POST',
                status_code=429,
                success=False,
                metadata={'reason': 'rate_limited'},
                correlation_id=getattr(request, 'correlation_id', ''),
            )
            return Response({'detail': 'Too many requests'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        serializer = TokenObtainPairSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data
            # Fetch user for audit
            username = request.data.get('username') or request.data.get('email')
            user = None
            if username:
                user = User.objects.filter(username=username).first()
            AuditEvent.objects.create(
                user=user,
                action='LOGIN_SUCCESS',
                ip=_client_ip(request),
                user_agent=_user_agent(request),
                path=request.path,
                method='POST',
                status_code=200,
                success=True,
                metadata={},
                correlation_id=getattr(request, 'correlation_id', ''),
            )
            return Response(data, status=status.HTTP_200_OK)

        AuditEvent.objects.create(
            user=None,
            action='LOGIN_FAIL',
            ip=_client_ip(request),
            user_agent=_user_agent(request),
            path=request.path,
            method='POST',
            status_code=401,
            success=False,
            metadata={'errors': serializer.errors},
            correlation_id=getattr(request, 'correlation_id', ''),
        )
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class RefreshView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Refresh Token",
        description="Renovação de token JWT usando refresh token",
        tags=['authentication'],
        responses={200: "Token renovado", 401: "Refresh token inválido"}
    )
    def post(self, request: HttpRequest):
        serializer = TokenRefreshSerializer(data=request.data)
        if serializer.is_valid():
            AuditEvent.objects.create(
                user=request.user if getattr(request, 'user', None) and request.user.is_authenticated else None,
                action='TOKEN_REFRESH',
                ip=_client_ip(request),
                user_agent=_user_agent(request),
                path=request.path,
                method='POST',
                status_code=200,
                success=True,
                metadata={},
                correlation_id=getattr(request, 'correlation_id', ''),
            )
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        AuditEvent.objects.create(
            user=request.user if getattr(request, 'user', None) and request.user.is_authenticated else None,
            action='TOKEN_REFRESH',
            ip=_client_ip(request),
            user_agent=_user_agent(request),
            path=request.path,
            method='POST',
            status_code=401,
            success=False,
            metadata={'errors': serializer.errors},
            correlation_id=getattr(request, 'correlation_id', ''),
        )
        return Response({'detail': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Logout",
        description="Logout de usuário com blacklist do refresh token",
        tags=['authentication'],
        responses={204: "Logout realizado", 400: "Token inválido"}
    )
    def post(self, request: HttpRequest):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            AuditEvent.objects.create(
                user=request.user if request.user.is_authenticated else None,
                action='LOGOUT',
                ip=_client_ip(request),
                user_agent=_user_agent(request),
                path=request.path,
                method='POST',
                status_code=400,
                success=False,
                metadata={'reason': 'missing_refresh'},
                correlation_id=getattr(request, 'correlation_id', ''),
            )
            return Response({'detail': 'Missing refresh token'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            AuditEvent.objects.create(
                user=request.user if request.user.is_authenticated else None,
                action='LOGOUT',
                ip=_client_ip(request),
                user_agent=_user_agent(request),
                path=request.path,
                method='POST',
                status_code=204,
                success=True,
                metadata={},
                correlation_id=getattr(request, 'correlation_id', ''),
            )
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception:
            AuditEvent.objects.create(
                user=request.user if request.user.is_authenticated else None,
                action='LOGOUT',
                ip=_client_ip(request),
                user_agent=_user_agent(request),
                path=request.path,
                method='POST',
                status_code=400,
                success=False,
                metadata={'reason': 'invalid_refresh'},
                correlation_id=getattr(request, 'correlation_id', ''),
            )
            return Response({'detail': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="Perfil do Usuário",
        description="Retorna informações do perfil do usuário autenticado",
        tags=['users'],
        responses={200: "Dados do perfil", 401: "Não autenticado"}
    )
    def get(self, request: HttpRequest):
        user = request.user
        profile_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser,
            'date_joined': user.date_joined.isoformat(),
            'last_login': user.last_login.isoformat() if user.last_login else None,
        }
        
        AuditEvent.objects.create(
            user=user,
            action='PROFILE_VIEW',
            ip=_client_ip(request),
            user_agent=_user_agent(request),
            path=request.path,
            method='GET',
            status_code=200,
            success=True,
            metadata={},
            correlation_id=getattr(request, 'correlation_id', ''),
        )
        
        return Response(profile_data, status=status.HTTP_200_OK)

    @extend_schema(
        summary="Atualizar Perfil",
        description="Atualiza informações do perfil do usuário",
        tags=['users'],
        responses={200: "Perfil atualizado", 400: "Dados inválidos", 401: "Não autenticado"}
    )
    def put(self, request: HttpRequest):
        user = request.user
        data = request.data
        
        # Campos permitidos para atualização
        allowed_fields = ['first_name', 'last_name', 'email']
        updated_fields = []
        
        for field in allowed_fields:
            if field in data:
                setattr(user, field, data[field])
                updated_fields.append(field)
        
        if updated_fields:
            try:
                user.save()
                AuditEvent.objects.create(
                    user=user,
                    action='PROFILE_UPDATE',
                    ip=_client_ip(request),
                    user_agent=_user_agent(request),
                    path=request.path,
                    method='PUT',
                    status_code=200,
                    success=True,
                    metadata={'updated_fields': updated_fields},
                    correlation_id=getattr(request, 'correlation_id', ''),
                )
                return Response({'message': 'Profile updated successfully'}, status=status.HTTP_200_OK)
            except Exception as e:
                AuditEvent.objects.create(
                    user=user,
                    action='PROFILE_UPDATE',
                    ip=_client_ip(request),
                    user_agent=_user_agent(request),
                    path=request.path,
                    method='PUT',
                    status_code=400,
                    success=False,
                    metadata={'error': str(e)},
                    correlation_id=getattr(request, 'correlation_id', ''),
                )
                return Response({'detail': 'Error updating profile'}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({'detail': 'No valid fields to update'}, status=status.HTTP_400_BAD_REQUEST)
