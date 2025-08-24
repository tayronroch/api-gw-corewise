from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    # API versioned routes
    path('api/v1/', include('api.v1.urls')),
    # Health endpoints
    path('health/', include('api.health.urls')),
    
    # API Documentation URLs
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    
    # API Endpoints
    path('api/topology/', include('modules.topology.urls')),
    path('api/networking/', include('modules.networking.urls')),
    # MPLS Analyzer - APIs REST documentadas
    path('api/mpls-analyzer/', include('modules.mpls_analyzer.api_urls')),
    # MPLS Analyzer - Interface web completa
    path('mpls-analyzer/', include('modules.mpls_analyzer.urls')),
    # Core APIs (Auth, Audit, etc.)
    path('api/core/', include('core.urls')),
]
