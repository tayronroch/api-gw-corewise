"""
URLs para o Core - Sistema Global de Auditoria CoreWise
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Router para ViewSets
router = DefaultRouter()
router.register(r'audit-logs', views.GlobalAuditLogViewSet)
router.register(r'access-logs', views.GlobalAccessLogViewSet)
router.register(r'security-settings', views.GlobalSecuritySettingsViewSet)
router.register(r'login-attempts', views.GlobalLoginAttemptViewSet)
router.register(r'user-activities', views.UserActivitySummaryViewSet)

urlpatterns = [
    # ViewSets REST padrão
    path('', include(router.urls)),
    
    # ==========================================
    # Endpoints de dashboard e relatórios
    # ==========================================
    path('security-dashboard/', views.security_dashboard, name='security-dashboard'),
    
    # ==========================================
    # Endpoints de manutenção e administração
    # ==========================================
    path('cleanup-logs/', views.cleanup_old_logs, name='cleanup-logs'),
    
    # ==========================================
    # Endpoints de monitoramento
    # ==========================================
    path('health/', views.health_check, name='health-check'),
    
    # ==========================================
    # API Gateway - Proxy genérico por serviço
    # ==========================================
    path('proxy/<str:service>/<path:path>', views.ProxyView.as_view(), name='api-proxy'),
    
    # ==========================================
    # Service Registry e Health
    # ==========================================
    path('services/', views.ServiceRegistryView.as_view(), name='service-registry'),
    path('services/health/', views.ServiceHealthView.as_view(), name='service-health'),

    # ==========================================
    # Auth Endpoints (JWT)
    # ==========================================
    path('auth/register', views.RegisterView.as_view(), name='auth-register'),
    path('auth/login', views.LoginView.as_view(), name='auth-login'),
    path('auth/refresh', views.RefreshView.as_view(), name='auth-refresh'),
    path('auth/logout', views.LogoutView.as_view(), name='auth-logout'),
]

# URLs com namespace
app_name = 'core'