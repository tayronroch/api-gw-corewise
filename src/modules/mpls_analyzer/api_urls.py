"""
URLs das APIs REST do MPLS Analyzer
Separadas das URLs tradicionais para incluir na documentação automática
"""
from django.urls import path
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from . import views

# Wrapper para converter function-based views em DRF APIViews para documentação
@extend_schema(
    summary="Busca MPLS",
    description="Busca inteligente por VPNs, equipamentos e configurações MPLS",
    tags=['mpls-search'],
    parameters=[
        OpenApiParameter(
            name='q',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Termo de busca (IP, VLAN, interface, etc.)',
            required=True
        )
    ],
    responses={200: "Lista de resultados da busca"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_search_documented(request):
    """Busca inteligente por configurações MPLS"""
    return views.api_search(request)

@extend_schema(
    summary="Relatório VPN",
    description="Relatório detalhado de uma VPN específica com informações de ponta A e B",
    tags=['mpls-reports'],
    parameters=[
        OpenApiParameter(
            name='vpn_id',
            type=OpenApiTypes.INT,
            location=OpenApiParameter.QUERY,
            description='ID da VPN',
            required=True
        )
    ],
    responses={200: "Detalhes da VPN"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def vpn_report_documented(request):
    """Relatório detalhado de VPN"""
    return views.vpn_report(request)

@extend_schema(
    summary="Relatório de Interfaces por Cliente",
    description="Lista interfaces de clientes por equipamento",
    tags=['mpls-reports'],
    parameters=[
        OpenApiParameter(
            name='equipment',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Nome do equipamento',
            required=True
        )
    ],
    responses={200: "Lista de interfaces do cliente"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def customer_interface_report_documented(request):
    """Relatório de interfaces por cliente"""
    return views.customer_interface_report(request)

@extend_schema(
    summary="Relatório de Cliente",
    description="Relatório completo de um cliente com todas suas VPNs",
    tags=['mpls-reports'],
    parameters=[
        OpenApiParameter(
            name='customer',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Nome do cliente',
            required=True
        )
    ],
    responses={200: "Relatório completo do cliente"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def customer_report_documented(request):
    """Relatório completo de cliente"""
    return views.customer_report(request)

@extend_schema(
    summary="Relatório Excel",
    description="Exporta relatório de cliente em formato Excel",
    tags=['mpls-admin'],
    parameters=[
        OpenApiParameter(
            name='customer',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Nome do cliente',
            required=True
        )
    ],
    responses={200: "Arquivo Excel"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def customer_report_excel_documented(request):
    """Exporta relatório em Excel"""
    return views.customer_report_excel(request)

urlpatterns = [
    path('search/', api_search_documented, name='mpls-api-search'),
    path('vpn-report/', vpn_report_documented, name='mpls-vpn-report'),
    path('customer-interface-report/', customer_interface_report_documented, name='mpls-customer-interface-report'),
    path('customer-report/', customer_report_documented, name='mpls-customer-report'),
    path('customer-report/excel/', customer_report_excel_documented, name='mpls-customer-report-excel'),
]