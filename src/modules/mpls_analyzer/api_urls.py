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
from .serializers import (
    SearchResponseSerializer, CustomerReportResponseSerializer, 
    EquipmentVPNsResponseSerializer, EquipmentJsonBackupResponseSerializer,
    ImportStatsSerializer, CollectAndImportRequestSerializer,
    ImportJsonsRequestSerializer, ErrorResponseSerializer
)

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
    responses={
        200: SearchResponseSerializer,
        400: ErrorResponseSerializer
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_search_documented(request):
    """Busca inteligente por configurações MPLS"""
    return views.api_search(request._request)

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
    return views.vpn_report(request._request)

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
    return views.customer_interface_report(request._request)

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
    return views.customer_report(request._request)

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
    return views.customer_report_excel(request._request)

@extend_schema(
    summary="Relatório de VPNs por Equipamento",
    description="Retorna todas as VPNs configuradas em um equipamento específico",
    tags=['mpls-reports'],
    parameters=[
        OpenApiParameter(
            name='equipment',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Nome do equipamento (ex: CE-TIANGUA-PE01)',
            required=True
        )
    ],
    responses={200: "Lista completa de VPNs do equipamento"}
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def equipment_vpns_report_documented(request):
    """Relatório de VPNs por equipamento"""
    return views.equipment_vpns_report(request._request)

@extend_schema(
    summary="JSON Backup Completo ou Filtrado do Equipamento",
    description="Retorna o backup JSON completo ou seções específicas de um equipamento DMOS",
    tags=['mpls-equipment'],
    parameters=[
        OpenApiParameter(
            name='equipment',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Nome ou ID do equipamento (ex: MA-BREJO-PE01 ou 8)',
            required=True
        ),
        OpenApiParameter(
            name='sections',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Seções específicas separadas por vírgula (ex: mpls,aaa,interfaces)',
            required=False
        ),
        OpenApiParameter(
            name='paths',
            type=OpenApiTypes.STR,
            location=OpenApiParameter.QUERY,
            description='Paths específicos separados por vírgula (ex: data.router-mpls:mpls.ldp-config)',
            required=False
        ),
        OpenApiParameter(
            name='metadata_only',
            type=OpenApiTypes.BOOL,
            location=OpenApiParameter.QUERY,
            description='Retorna apenas metadados sem o JSON (default: false)',
            required=False
        )
    ],
    responses={
        200: EquipmentJsonBackupResponseSerializer,
        404: ErrorResponseSerializer,
        400: ErrorResponseSerializer
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def equipment_json_backup_documented(request):
    """JSON backup completo do equipamento"""
    return views.equipment_json_backup(request._request)

# Documentação para o endpoint de atualização (import JSONs)
@extend_schema(
    summary="Importa backups JSON",
    description=(
        "Dispara a importação dos arquivos JSON coletados via SSH e atualiza o banco. "
        "Por padrão lê de modules/mpls_analyzer/update. Requer permissão de manager/admin."
    ),
    tags=['mpls-admin'],
    request=ImportJsonsRequestSerializer,
    responses={200: ImportStatsSerializer}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def import_jsons_update_documented(request):
    return views.import_jsons_update(request._request)


@extend_schema(
    summary="Coletar e importar JSONs",
    description=(
        "Conecta em todos os equipamentos com as credenciais fornecidas, coleta a configuração em JSON "
        "(comando configurável) e importa no banco. Retorna um log_id para acompanhamento."
    ),
    tags=['mpls-admin'],
    request=CollectAndImportRequestSerializer,
    responses={200: ImportStatsSerializer}
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def collect_and_import_update_documented(request):
    return views.collect_and_import_update(request._request)

urlpatterns = [
    path('search/', api_search_documented, name='mpls-api-search'),
    path('search/suggestions/', api_search_documented, name='mpls-api-search-suggestions'),  # Sugestões usam mesma lógica de busca
    path('reports/customers/', customer_report_documented, name='mpls-api-customer-report'),  # URL esperada pelo frontend
    path('reports/equipment/', equipment_vpns_report_documented, name='mpls-api-equipment-report'),  # Nova URL para VPNs por equipamento
    path('equipment/json-backup/', equipment_json_backup_documented, name='mpls-api-equipment-json-backup'),  # Novo endpoint para JSON backup completo
    path('vpn-report/', vpn_report_documented, name='mpls-vpn-report'),
    path('customer-interface-report/', customer_interface_report_documented, name='mpls-customer-interface-report'),
    path('customer-report/', customer_report_documented, name='mpls-customer-report'),
    path('customer-report/excel/', customer_report_excel_documented, name='mpls-customer-report-excel'),
    # Admin/update endpoints POST - update do banco de dados
    path('update/import-jsons/', import_jsons_update_documented, name='mpls-update-import-jsons'),
    path('update/collect-and-import/', collect_and_import_update_documented, name='mpls-collect-and-import'),
    path('update/status/<int:log_id>/', views.update_status, name='mpls-update-status'),
]
