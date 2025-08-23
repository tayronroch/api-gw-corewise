"""
URLs de compatibilidade para o sistema MPLS original.
Rotas legacy com cabeçalhos de depreciação e marcadas como deprecated no OpenAPI.
"""
from django.urls import path
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from modules.mpls_analyzer import views as mpls_views


def add_deprecation_headers(resp):
    resp["Deprecation"] = "true"
    resp["Sunset"] = (timezone.now() + timezone.timedelta(days=180)).strftime('%a, %d %b %Y %H:%M:%S GMT')
    resp["Link"] = '<https://github.com/your-org/CoreWise>; rel="documentation"'
    return resp


@extend_schema(deprecated=True, tags=['mpls-legacy'])
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def legacy_advanced_search(request):
    resp = mpls_views.advanced_search(request)
    return add_deprecation_headers(resp)


@extend_schema(deprecated=True, tags=['mpls-legacy'])
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def legacy_api_search(request):
    resp = mpls_views.intelligent_search(request)
    return add_deprecation_headers(resp)


@extend_schema(deprecated=True, tags=['mpls-legacy'])
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def legacy_customer_report(request):
    resp = mpls_views.customer_report(request)
    return add_deprecation_headers(resp)


@extend_schema(deprecated=True, tags=['mpls-legacy'])
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def legacy_customer_report_excel(request):
    # Mapeia para CSV compatível com Excel
    resp = mpls_views.customer_report_excel(request)
    return add_deprecation_headers(resp)


@extend_schema(deprecated=True, tags=['mpls-legacy'])
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def legacy_vpn_report(request):
    resp = mpls_views.vpn_report(request)
    return add_deprecation_headers(resp)


@extend_schema(deprecated=True, tags=['mpls-legacy'])
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def legacy_customer_interface_report(request):
    resp = mpls_views.customer_interface_report(request)
    return add_deprecation_headers(resp)


@extend_schema(deprecated=True, tags=['mpls-legacy'])
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def legacy_update_status(request):
    resp = mpls_views.system_statistics(request)
    return add_deprecation_headers(resp)


urlpatterns = [
    path('advanced-search/', legacy_advanced_search, name='legacy-advanced-search'),
    path('api/search/', legacy_api_search, name='legacy-api-search'),
    path('api/customer-report/', legacy_customer_report, name='legacy-customer-report'),
    path('api/customer-report/excel/', legacy_customer_report_excel, name='legacy-customer-report-excel'),
    path('api/vpn-report/', legacy_vpn_report, name='legacy-vpn-report'),
    path('api/customer-interface-report/', legacy_customer_interface_report, name='legacy-customer-interface-report'),
    path('api/update-status/', legacy_update_status, name='legacy-update-status'),
]
