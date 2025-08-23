from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # API Documentation URLs
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    
    # API Endpoints
    path('api/users/', include('users.urls')),
    path('api/topology/', include('modules.topology.urls')),
    path('api/engineering/', include('engineering.urls')),
    path('api/security/', include('security.urls')),
    path('api/networking/', include('modules.networking.urls')),
    path('api/mpls-analyzer/', include('modules.mpls_analyzer.urls')),
    # Legacy compat para rotas antigas do sistema MPLS
    path('api/mpls/legacy/', include('modules.mpls_legacy.urls')),
    path('api/core/', include('core.urls')),
]
