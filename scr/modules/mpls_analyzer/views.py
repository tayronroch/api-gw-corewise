"""
Django REST Framework views para MPLS Analyzer
Sistema integrado ao CoreWise mantendo funcionalidades críticas
"""
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import api_view, action, permission_classes
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from django.contrib.auth.models import User
from django.db.models import Q, Count
from django.utils import timezone
from datetime import timedelta
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from .models import (
    Equipment, MplsConfiguration, VpwsGroup, Vpn, LdpNeighbor,
    Interface, LagMember, CustomerService, BackupProcessLog,
    AccessLog, AuditLog, SecuritySettings, LoginAttempt, UserProfile
)
from .serializers import (
    EquipmentSerializer, MplsConfigurationSerializer, VpwsGroupSerializer,
    VpnSerializer, LdpNeighborSerializer, InterfaceSerializer,
    CustomerServiceSerializer, BackupProcessLogSerializer, AccessLogSerializer,
    AuditLogSerializer, SecuritySettingsSerializer, LoginAttemptSerializer,
    UserProfileSerializer, SearchResultSerializer, CustomerReportSerializer,
    EquipmentSummarySerializer, SearchQuerySerializer
)
from .search_utils import smart_search, AdvancedSearchEngine
import csv
from io import StringIO


class EquipmentViewSet(viewsets.ModelViewSet):
    """ViewSet para gerenciar equipamentos MPLS"""
    queryset = Equipment.objects.all()
    serializer_class = EquipmentSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['equipment_type', 'status', 'location']
    search_fields = ['name', 'ip_address', 'location']
    ordering_fields = ['name', 'equipment_type', 'last_backup']
    ordering = ['name']


class MplsConfigurationViewSet(viewsets.ModelViewSet):
    """ViewSet para configurações MPLS"""
    queryset = MplsConfiguration.objects.select_related('equipment').all()
    serializer_class = MplsConfigurationSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['equipment', 'equipment__equipment_type']
    search_fields = ['equipment__name', 'raw_config']
    ordering_fields = ['backup_date', 'processed_at']
    ordering = ['-backup_date']


class VpwsGroupViewSet(viewsets.ModelViewSet):
    """ViewSet para grupos VPWS"""
    queryset = VpwsGroup.objects.select_related('mpls_config__equipment').all()
    serializer_class = VpwsGroupSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['mpls_config__equipment']
    search_fields = ['group_name', 'mpls_config__equipment__name']
    ordering = ['group_name']


class VpnViewSet(viewsets.ModelViewSet):
    """ViewSet para VPNs MPLS"""
    queryset = Vpn.objects.select_related('vpws_group__mpls_config__equipment').all()
    serializer_class = VpnSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['vpn_id', 'encapsulation_type', 'vpws_group__mpls_config__equipment']
    search_fields = ['description', 'neighbor_ip', 'neighbor_hostname']
    ordering_fields = ['vpn_id', 'description']
    ordering = ['vpn_id']


class LdpNeighborViewSet(viewsets.ModelViewSet):
    """ViewSet para vizinhos LDP"""
    queryset = LdpNeighbor.objects.select_related('mpls_config__equipment').all()
    serializer_class = LdpNeighborSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['targeted', 'mpls_config__equipment']
    search_fields = ['neighbor_ip', 'mpls_config__equipment__name']
    ordering = ['neighbor_ip']


class InterfaceViewSet(viewsets.ModelViewSet):
    """ViewSet para interfaces MPLS"""
    queryset = Interface.objects.select_related('mpls_config__equipment').all()
    serializer_class = InterfaceSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['interface_type', 'is_customer_interface', 'mpls_config__equipment']
    search_fields = ['name', 'description', 'speed']
    ordering_fields = ['name', 'interface_type']
    ordering = ['name']


class CustomerServiceViewSet(viewsets.ModelViewSet):
    """ViewSet para serviços de clientes"""
    queryset = CustomerService.objects.select_related('vpn__vpws_group__mpls_config__equipment').all()
    serializer_class = CustomerServiceSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['service_type', 'vpn__vpws_group__mpls_config__equipment']
    search_fields = ['name', 'bandwidth']
    ordering_fields = ['name', 'service_type', 'created_at']
    ordering = ['name']


class BackupProcessLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet para logs de processamento (somente leitura)"""
    queryset = BackupProcessLog.objects.all()
    serializer_class = BackupProcessLogSerializer
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['status', 'user']
    ordering_fields = ['started_at', 'finished_at']
    ordering = ['-started_at']


class AccessLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet para logs de acesso (somente leitura)"""
    queryset = AccessLog.objects.select_related('user').all()
    serializer_class = AccessLogSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['status', 'user']
    search_fields = ['user__username', 'ip_address']
    ordering_fields = ['login_time', 'logout_time']
    ordering = ['-login_time']


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet para logs de auditoria (somente leitura)"""
    queryset = AuditLog.objects.select_related('user').all()
    serializer_class = AuditLogSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['action', 'user', 'target_object_type']
    search_fields = ['user__username', 'description', 'search_query']
    ordering_fields = ['timestamp']
    ordering = ['-timestamp']


class LoginAttemptViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet para tentativas de login (somente leitura)"""
    queryset = LoginAttempt.objects.all()
    serializer_class = LoginAttemptSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['success', 'username']
    search_fields = ['username', 'ip_address']
    ordering_fields = ['timestamp']
    ordering = ['-timestamp']


class UserProfileViewSet(viewsets.ModelViewSet):
    """ViewSet para perfis de usuários MPLS"""
    queryset = UserProfile.objects.select_related('user').all()
    serializer_class = UserProfileSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['require_mfa', 'is_admin', 'mfa_enabled']
    search_fields = ['user__username', 'user__email']
    ordering = ['user__username']


# ==========================================
# Endpoints de busca inteligente
# ==========================================

@api_view(['GET', 'POST'])
@permission_classes([permissions.AllowAny])
def intelligent_search(request):
    """
    Busca inteligente que detecta automaticamente o tipo de busca
    Preserva a funcionalidade original do sistema
    """
    if request.method == 'GET':
        query = request.GET.get('q', '')
    else:
        serializer = SearchQuerySerializer(data=request.data)
        if serializer.is_valid():
            query = serializer.validated_data['query']
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    if not query:
        return Response({'error': 'Query parameter required'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Parâmetros opcionais
    search_type = request.GET.get('type', request.data.get('search_type', 'auto'))
    try:
        limit = int(request.GET.get('limit', request.data.get('limit', 50)))
    except Exception:
        limit = 50
    include_config = str(request.GET.get('include_config', request.data.get('include_config', 'false'))).lower() == 'true'

    # Executa a busca usando o motor avançado
    engine = AdvancedSearchEngine()
    
    if search_type == 'auto':
        # Detecta tipo automaticamente
        results = smart_search(query, search_type='auto')
    else:
        # Usa tipo específico
        if search_type == 'vpn':
            results = engine.search_vpn_id(query)
        elif search_type == 'ip':
            results = engine.search_ip_addresses(query)
        elif search_type == 'mac':
            results = engine.search_mac_addresses(query)
        elif search_type == 'serial':
            results = engine.search_serial_numbers(query)
        elif search_type == 'interface':
            results = engine.search_interfaces(query)
        elif search_type == 'vlan':
            results = engine.search_vlans(query)
        else:
            results = engine.search_full_text(query, limit=limit)

    # Converte para lista e aplica limite
    if hasattr(results, '__getitem__'):
        results_list = list(results[:limit])
    else:
        results_list = list(results)[:limit]

    # Monta resultados detalhados incluindo VPNs e clientes
    payload = []
    for cfg in results_list:
        try:
            # Busca VPNs relacionadas a este equipamento
            vpns = Vpn.objects.filter(
                vpws_group__mpls_config=cfg
            ).select_related('vpws_group').prefetch_related('customer_services')
            
            if vpns.exists():
                for vpn in vpns:
                    # Para cada VPN, busca serviços de cliente
                    services = vpn.customer_services.all()
                    
                    if services.exists():
                        for service in services:
                            item = {
                                'equipment_name': cfg.equipment.name,
                                'equipment_type': cfg.equipment.equipment_type,
                                'equipment_location': cfg.equipment.location,
                                'equipment_ip': cfg.equipment.ip_address,
                                'vpn_id': vpn.vpn_id,
                                'vpn_description': vpn.description or '',
                                'customer_name': service.name,
                                'service_type': service.get_service_type_display(),
                                'bandwidth': service.bandwidth,
                                'access_interface': vpn.access_interface or '',
                                'encapsulation': vpn.encapsulation or '',
                                'neighbor_ip': vpn.neighbor_ip or '',
                                'match_type': 'vpn_service',
                                'match_text': query,
                                'backup_date': cfg.backup_date.isoformat() if cfg.backup_date else None,
                            }
                            
                            if include_config:
                                snippets = engine.extract_search_highlights(cfg.raw_config, query, max_snippets=2)
                                item['highlights'] = snippets
                                
                            payload.append(item)
                    else:
                        # VPN sem serviços
                        item = {
                            'equipment_name': cfg.equipment.name,
                            'equipment_type': cfg.equipment.equipment_type,
                            'equipment_location': cfg.equipment.location,
                            'equipment_ip': cfg.equipment.ip_address,
                            'vpn_id': vpn.vpn_id,
                            'vpn_description': vpn.description or '',
                            'customer_name': '',
                            'service_type': '',
                            'bandwidth': '',
                            'access_interface': vpn.access_interface or '',
                            'encapsulation': vpn.encapsulation or '',
                            'neighbor_ip': vpn.neighbor_ip or '',
                            'match_type': 'vpn',
                            'match_text': query,
                            'backup_date': cfg.backup_date.isoformat() if cfg.backup_date else None,
                        }
                        
                        if include_config:
                            snippets = engine.extract_search_highlights(cfg.raw_config, query, max_snippets=2)
                            item['highlights'] = snippets
                            
                        payload.append(item)
            else:
                # Configuração sem VPNs
                item = {
                    'equipment_name': cfg.equipment.name,
                    'equipment_type': cfg.equipment.equipment_type,
                    'equipment_location': cfg.equipment.location,
                    'equipment_ip': cfg.equipment.ip_address,
                    'vpn_id': None,
                    'vpn_description': '',
                    'customer_name': '',
                    'service_type': '',
                    'bandwidth': '',
                    'access_interface': '',
                    'encapsulation': '',
                    'neighbor_ip': '',
                    'match_type': 'config',
                    'match_text': query,
                    'backup_date': cfg.backup_date.isoformat() if cfg.backup_date else None,
                }
                
                if include_config:
                    snippets = engine.extract_search_highlights(cfg.raw_config, query, max_snippets=2)
                    item['highlights'] = snippets
                    
                payload.append(item)
                
        except Exception as e:
            # Log error but continue processing
            continue

    return Response({
        'query': query,
        'results': payload,
        'total': len(payload),
        'search_type': search_type or 'auto'
    })


@api_view(['POST', 'GET'])
@permission_classes([permissions.IsAuthenticated])
def advanced_search(request):
    """
    Busca avançada com filtros específicos
    Permite filtrar por equipamento, localização, tipo de serviço, etc.
    """
    # Obter parâmetros da requisição
    if request.method == 'POST':
        data = request.data
    else:
        data = request.GET
    
    query = data.get('query', '').strip()
    equipment_filter = data.get('equipment', '').strip()
    location_filter = data.get('location', '').strip()
    service_type_filter = data.get('service_type', '').strip().lower()
    vpn_id_filter = data.get('vpn_id', '').strip()
    customer_filter = data.get('customer', '').strip()
    interface_filter = data.get('interface', '').strip()
    
    try:
        limit = int(data.get('limit', 100))
    except:
        limit = 100
        
    # Busca baseada em VPNs para melhor performance
    vpn_qs = (
        Vpn.objects.select_related('vpws_group__mpls_config__equipment')
        .prefetch_related('customer_services')
    )
    
    # Aplicar filtros
    if vpn_id_filter:
        try:
            vpn_qs = vpn_qs.filter(vpn_id=int(vpn_id_filter))
        except ValueError:
            pass
    
    if equipment_filter:
        vpn_qs = vpn_qs.filter(
            vpws_group__mpls_config__equipment__name__icontains=equipment_filter
        )
    
    if location_filter:
        vpn_qs = vpn_qs.filter(
            vpws_group__mpls_config__equipment__location__icontains=location_filter
        )
    
    if customer_filter:
        vpn_qs = vpn_qs.filter(
            customer_services__name__icontains=customer_filter
        )
    
    if service_type_filter:
        # Verificar se é um tipo de serviço válido
        valid_types = [choice[0] for choice in CustomerService.SERVICE_TYPE_CHOICES]
        if service_type_filter in valid_types:
            vpn_qs = vpn_qs.filter(customer_services__service_type=service_type_filter)
    
    if interface_filter:
        vpn_qs = vpn_qs.filter(access_interface__icontains=interface_filter)
    
    if query:
        # Busca textual geral
        vpn_qs = vpn_qs.filter(
            Q(vpws_group__mpls_config__equipment__name__icontains=query) |
            Q(vpws_group__mpls_config__equipment__location__icontains=query) |
            Q(description__icontains=query) |
            Q(access_interface__icontains=query) |
            Q(customer_services__name__icontains=query) |
            Q(neighbor_hostname__icontains=query)
        )
    
    vpn_qs = vpn_qs.distinct()[:limit]
    
    # Montar resultados
    results = []
    for vpn in vpn_qs:
        equipment = vpn.vpws_group.mpls_config.equipment
        vpws_group = vpn.vpws_group
        
        # Buscar equipamento vizinho
        neighbor_equipment = None
        if vpn.neighbor_ip:
            try:
                neighbor_equipment = Equipment.objects.get(ip_address=vpn.neighbor_ip)
            except Equipment.DoesNotExist:
                pass
        
        # Buscar detalhes da interface
        interface_details = None
        if vpn.access_interface:
            try:
                interface = Interface.objects.get(
                    mpls_config=vpws_group.mpls_config,
                    name=vpn.access_interface
                )
                interface_details = {
                    'name': interface.name,
                    'description': interface.description or '',
                    'type': interface.interface_type,
                    'speed': interface.speed or '',
                    'status': 'active'  # Interface não tem campo status, usar valor padrão
                }
                
                # Se for LAG, buscar membros
                if interface.interface_type == 'lag':
                    members = interface.members.values_list('member_interface_name', flat=True)
                    interface_details['lag_members'] = list(members)
                    
            except Interface.DoesNotExist:
                interface_details = {
                    'name': vpn.access_interface,
                    'description': '',
                    'type': 'unknown',
                    'speed': '',
                    'status': 'unknown'
                }
        
        # Serviços de cliente para esta VPN
        services = list(vpn.customer_services.all())
        
        if services:
            for service in services:
                results.append({
                    'customer_name': service.name,
                    'service_type': service.get_service_type_display(),
                    'bandwidth': service.bandwidth or '',
                    'equipment_name': equipment.name,
                    'equipment_type': equipment.equipment_type,
                    'equipment_ip': equipment.ip_address,
                    'location': equipment.location,
                    'vpn_id': vpn.vpn_id,
                    'vpn_description': vpn.description or '',
                    'access_interface': vpn.access_interface or '',
                    'interface_details': interface_details,
                    'encapsulation': vpn.encapsulation or '',
                    'encapsulation_type': vpn.encapsulation_type or '',
                    'neighbor_ip': vpn.neighbor_ip or '',
                    'neighbor_hostname': vpn.neighbor_hostname or '',
                    'neighbor_equipment': neighbor_equipment.name if neighbor_equipment else '',
                    'vpws_group_name': vpws_group.group_name,
                    'pw_type': vpn.pw_type or '',
                    'pw_id': vpn.pw_id,
                    'backup_date': equipment.last_backup.isoformat() if equipment.last_backup else None,
                })
        else:
            # VPN sem serviços
            results.append({
                'customer_name': '',
                'service_type': '',
                'bandwidth': '',
                'equipment_name': equipment.name,
                'equipment_type': equipment.equipment_type,
                'equipment_ip': equipment.ip_address,
                'location': equipment.location,
                'vpn_id': vpn.vpn_id,
                'vpn_description': vpn.description or '',
                'access_interface': vpn.access_interface or '',
                'interface_details': interface_details,
                'encapsulation': vpn.encapsulation or '',
                'encapsulation_type': vpn.encapsulation_type or '',
                'neighbor_ip': vpn.neighbor_ip or '',
                'neighbor_hostname': vpn.neighbor_hostname or '',
                'neighbor_equipment': neighbor_equipment.name if neighbor_equipment else '',
                'vpws_group_name': vpws_group.group_name,
                'pw_type': vpn.pw_type or '',
                'pw_id': vpn.pw_id,
                'backup_date': equipment.last_backup.isoformat() if equipment.last_backup else None,
            })
    
    return Response({
        'total': len(results),
        'results': results,
        'filters_applied': {
            'query': query,
            'equipment': equipment_filter,
            'location': location_filter,
            'service_type': service_type_filter,
            'vpn_id': vpn_id_filter,
            'customer': customer_filter,
            'interface': interface_filter,
        }
    })


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def search_suggestions(request):
    """Sugestões de busca baseadas na query atual"""
    query = request.GET.get('q', '')
    suggestions = []
    
    if len(query) >= 2:
        # Buscar equipamentos
        equipment_suggestions = Equipment.objects.filter(
            name__icontains=query
        ).values_list('name', flat=True)[:5]
        suggestions.extend(equipment_suggestions)
        
        # Buscar clientes
        customer_suggestions = CustomerService.objects.filter(
            name__icontains=query
        ).values_list('name', flat=True).distinct()[:5]
        suggestions.extend(customer_suggestions)
    
    return Response({'suggestions': list(suggestions)})


# ==========================================
# Endpoints de relatórios
# ==========================================

@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def customer_report(request):
    """
    Relatório detalhado de clientes - implementação completa
    Preserva a funcionalidade original do sistema MPLS
    """
    customer_name = request.GET.get('customer')
    
    if customer_name:
        # Primeiro tentar buscar nos serviços de cliente
        services = CustomerService.objects.filter(
            name__icontains=customer_name
        ).select_related(
            'vpn__vpws_group__mpls_config__equipment'
        ).prefetch_related(
            'vpn__customer_services'
        )
        
        # Se não encontrar nos serviços, buscar nas configurações
        if not services.exists():
            # Buscar equipamentos que têm o termo nas configurações
            configs_with_customer = MplsConfiguration.objects.filter(
                raw_config__icontains=customer_name
            ).select_related('equipment').distinct()
            
            if not configs_with_customer.exists():
                return Response({
                    'error': 'Cliente não encontrado',
                    'customer': customer_name
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Criar relatório baseado nas configurações encontradas
            equipment_groups = {}
            for config in configs_with_customer:
                equipment = config.equipment
                group_key = f"{equipment.name}|{equipment.location}"
                
                if group_key not in equipment_groups:
                    equipment_groups[group_key] = {
                        'equipment_name': equipment.name,
                        'equipment_type': equipment.equipment_type or 'PE',
                        'equipment_ip': equipment.ip_address,
                        'location': equipment.location,
                        'backup_date': config.backup_date.isoformat() if config.backup_date else None,
                        'config_mentions': 1,
                        'services': []  # Vazio já que não há serviços estruturados
                    }
                else:
                    equipment_groups[group_key]['config_mentions'] += 1
            
            # Retornar relatório baseado em configurações
            return Response({
                'customer_name': customer_name,
                'total_locations': len(equipment_groups),
                'total_equipments': len(equipment_groups), 
                'total_configs_with_mentions': sum(g['config_mentions'] for g in equipment_groups.values()),
                'search_type': 'configuration_search',
                'groups': [
                    {
                        'location': group['location'],
                        'equipments': [{
                            'name': group['equipment_name'],
                            'type': group['equipment_type'],
                            'ip_address': group['equipment_ip'],
                            'last_backup': group['backup_date'],
                            'config_mentions': group['config_mentions'],
                            'interfaces': []  # Vazio para busca em configs
                        }]
                    } 
                    for group in equipment_groups.values()
                ]
            })
        
        # Se encontrou serviços, continuar com a lógica original
        if not services.exists():
            return Response({
                'error': 'Cliente não encontrado nos serviços',
                'customer': customer_name
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Agrupar serviços por equipamento/localização
        equipment_groups = {}
        total_services = 0
        total_bandwidth = 0
        
        for service in services:
            total_services += 1
            try:
                if service.bandwidth and service.bandwidth.replace('M', '').replace('G', '').isdigit():
                    bw_value = int(service.bandwidth.replace('M', '').replace('G', ''))
                    if 'G' in service.bandwidth:
                        bw_value *= 1000  # Converter para Mbps
                    total_bandwidth += bw_value
            except:
                pass
            
            vpn = service.vpn
            equipment = vpn.vpws_group.mpls_config.equipment
            
            # Chave para agrupamento
            group_key = f"{equipment.name}|{equipment.location}"
            
            if group_key not in equipment_groups:
                equipment_groups[group_key] = {
                    'equipment_name': equipment.name,
                    'equipment_type': equipment.equipment_type,
                    'equipment_ip': equipment.ip_address,
                    'location': equipment.location,
                    'services': [],
                    'vpns': set(),
                    'total_vpns': 0,
                    'service_types': set()
                }
            
            # Buscar equipamento vizinho
            neighbor_equipment = None
            if vpn.neighbor_ip:
                try:
                    # Usar filter().first() para evitar erro quando há múltiplos equipamentos com mesmo IP
                    neighbor_equipment = Equipment.objects.filter(ip_address=vpn.neighbor_ip).first()
                except Exception:
                    pass
            
            # Buscar interface details
            interface_details = None
            opposite_interface_details = None
            
            if vpn.access_interface:
                try:
                    interface = Interface.objects.get(
                        mpls_config=vpn.vpws_group.mpls_config,
                        name=vpn.access_interface
                    )
                    interface_details = {
                        'name': interface.name,
                        'description': interface.description or '',
                        'type': interface.interface_type,
                        'speed': interface.speed or '',
                        'status': 'active'  # Interface não tem campo status, usar valor padrão
                    }
                    
                    if interface.interface_type == 'lag':
                        members = interface.members.values_list('member_interface_name', flat=True)
                        interface_details['lag_members'] = list(members)
                        
                except Interface.DoesNotExist:
                    interface_details = {
                        'name': vpn.access_interface,
                        'description': 'Interface não encontrada no backup',
                        'type': 'unknown',
                        'speed': '',
                        'status': 'unknown'
                    }
                
                # Buscar interface oposta se houver equipamento vizinho
                if neighbor_equipment:
                    try:
                        opposite_vpn = Vpn.objects.filter(
                            vpn_id=vpn.vpn_id,
                            neighbor_ip=equipment.ip_address
                        ).first()
                        
                        if opposite_vpn and opposite_vpn.access_interface:
                            opposite_interface = Interface.objects.filter(
                                mpls_config__equipment=neighbor_equipment,
                                name=opposite_vpn.access_interface
                            ).first()
                            
                            if opposite_interface:
                                opposite_interface_details = {
                                    'name': opposite_interface.name,
                                    'description': opposite_interface.description or '',
                                    'type': opposite_interface.interface_type,
                                    'speed': opposite_interface.speed or '',
                                    'status': 'active'  # Interface não tem campo status, usar valor padrão
                                }
                                
                                if opposite_interface.interface_type == 'lag':
                                    members = opposite_interface.members.values_list('member_interface_name', flat=True)
                                    opposite_interface_details['lag_members'] = list(members)
                    except:
                        pass
            
            # Adicionar serviço ao grupo
            service_data = {
                'service_name': service.name,
                'service_type': service.get_service_type_display(),
                'bandwidth': service.bandwidth or '',
                'vpn_id': vpn.vpn_id,
                'vpn_description': vpn.description or '',
                'access_interface': vpn.access_interface or '',
                'interface_details': interface_details,
                'opposite_interface_details': opposite_interface_details,
                'encapsulation': vpn.encapsulation or '',
                'encapsulation_type': vpn.encapsulation_type or '',
                'neighbor_ip': vpn.neighbor_ip or '',
                'neighbor_hostname': vpn.neighbor_hostname or '',
                'neighbor_equipment': neighbor_equipment.name if neighbor_equipment else '',
                'vpws_group_name': vpn.vpws_group.group_name,
                'pw_type': vpn.pw_type or '',
                'pw_id': vpn.pw_id,
                'last_backup': equipment.last_backup.isoformat() if equipment.last_backup else None,
            }
            
            equipment_groups[group_key]['services'].append(service_data)
            equipment_groups[group_key]['vpns'].add(vpn.vpn_id)
            equipment_groups[group_key]['service_types'].add(service.service_type)
        
        # Converter sets para listas e calcular totais
        for group in equipment_groups.values():
            group['total_vpns'] = len(group['vpns'])
            group['vpns'] = sorted(list(group['vpns']))
            group['service_types'] = list(group['service_types'])
        
        return Response({
            'customer': customer_name,
            'summary': {
                'total_services': total_services,
                'total_bandwidth_mbps': total_bandwidth,
                'total_equipment': len(equipment_groups),
                'locations': list(set(group['location'] for group in equipment_groups.values())),
                'service_types': list(set().union(*(group['service_types'] for group in equipment_groups.values())))
            },
            'equipment_groups': list(equipment_groups.values()),
            'generated_at': timezone.now().isoformat()
        })
    
    # Lista todos os clientes com estatísticas
    customers = []
    customer_stats = CustomerService.objects.values('name').annotate(
        service_count=Count('id'),
        vpn_count=Count('vpn_id', distinct=True),
        equipment_count=Count('vpn__vpws_group__mpls_config__equipment', distinct=True)
    ).order_by('-service_count')
    
    for customer in customer_stats[:500]:  # Limitar para performance
        # Buscar tipos de serviço únicos
        service_types = CustomerService.objects.filter(
            name=customer['name']
        ).values_list('service_type', flat=True).distinct()
        
        # Buscar localizações únicas
        locations = CustomerService.objects.filter(
            name=customer['name']
        ).select_related(
            'vpn__vpws_group__mpls_config__equipment'
        ).values_list(
            'vpn__vpws_group__mpls_config__equipment__location', 
            flat=True
        ).distinct()
        
        customers.append({
            'name': customer['name'],
            'service_count': customer['service_count'],
            'vpn_count': customer['vpn_count'],
            'equipment_count': customer['equipment_count'],
            'service_types': list(service_types),
            'locations': [loc for loc in locations if loc],
        })
    
    return Response({
        'total_customers': len(customers),
        'customers': customers,
        'generated_at': timezone.now().isoformat()
    })


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def vpn_report(request):
    """Relatório de VPNs. Filtro opcional por vpn_id ou equipment."""
    vpn_id = request.GET.get('vpn_id')
    equipment = request.GET.get('equipment')
    qs = Vpn.objects.select_related('vpws_group__mpls_config__equipment').all()
    if vpn_id:
        try:
            qs = qs.filter(vpn_id=int(vpn_id))
        except ValueError:
            return Response({'error': 'vpn_id inválido'}, status=status.HTTP_400_BAD_REQUEST)
    if equipment:
        qs = qs.filter(vpws_group__mpls_config__equipment__name__icontains=equipment)
    serializer = VpnSerializer(qs.order_by('vpn_id')[:500], many=True)
    return Response({'count': qs.count(), 'results': serializer.data})


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def customer_interface_report(request):
    """Relatório de interfaces por cliente, baseado no vínculo CustomerService -> Vpn.access_interface."""
    customer = request.GET.get('customer')
    qs = CustomerService.objects.select_related('vpn__vpws_group__mpls_config__equipment')
    if customer:
        qs = qs.filter(name__icontains=customer)
    data = []
    for svc in qs[:1000]:
        vpn = svc.vpn
        equip = vpn.vpws_group.mpls_config.equipment
        data.append({
            'customer': svc.name,
            'service_type': svc.service_type,
            'equipment': equip.name,
            'equipment_type': equip.equipment_type,
            'location': equip.location,
            'vpn_id': vpn.vpn_id,
            'vpn_description': vpn.description,
            'access_interface': vpn.access_interface,
            'bandwidth': svc.bandwidth,
        })
    return Response({'count': qs.count(), 'results': data})


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def customer_report_excel(request):
    """Exporta o relatório de clientes em formato CSV com content-type Excel-compatible."""
    # Reutiliza a lógica de customer_report para obter dados agregados
    customer_name = request.GET.get('customer')
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(['Customer', 'ServicesCount'])

    if customer_name:
        services = CustomerService.objects.filter(name__icontains=customer_name)
        writer.writerow([customer_name, services.count()])
    else:
        customers = CustomerService.objects.values('name').annotate(service_count=Count('id')).order_by('-service_count')
        for c in customers:
            writer.writerow([c['name'], c['service_count']])

    resp = Response(buffer.getvalue())
    resp['Content-Type'] = 'application/vnd.ms-excel'
    filename = f"customer_report_{timezone.now().strftime('%Y%m%d_%H%M%S')}.csv"
    resp['Content-Disposition'] = f'attachment; filename="{filename}"'
    return resp


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def equipment_summary(request):
    """Resumo de equipamentos"""
    equipments = Equipment.objects.annotate(
        vpns_count=Count('mpls_configs__vpws_groups__vpns'),
        interfaces_count=Count('mpls_configs__interfaces')
    ).order_by('name')
    
    serializer = EquipmentSummarySerializer(equipments, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def network_topology(request):
    """Dados para visualização da topologia de rede"""
    # TODO: Implementar geração de dados de topologia
    return Response({
        'nodes': [],
        'links': [],
        'statistics': {}
    })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def export_report(request):
    """Exportar relatórios em diferentes formatos"""
    # TODO: Implementar exportação
    return Response({'message': 'Export functionality - TODO'})


# ==========================================
# Endpoints de administração
# ==========================================

@api_view(['POST'])
@permission_classes([permissions.IsAdminUser])
def process_backups(request):
    """Processar novos backups (preserva funcionalidade original)"""
    # TODO: Integrar com parsers.py preservado
    return Response({'message': 'Backup processing started'})


@api_view(['POST'])
@permission_classes([permissions.IsAdminUser])
def bulk_update_equipment(request):
    """Atualização em lote de equipamentos"""
    # TODO: Implementar atualização em lote
    return Response({'message': 'Bulk update - TODO'})


@api_view(['GET', 'POST'])
@permission_classes([permissions.IsAdminUser])
def security_settings(request):
    """Gerenciar configurações de segurança"""
    settings_obj = SecuritySettings.get_settings()
    
    if request.method == 'GET':
        serializer = SecuritySettingsSerializer(settings_obj)
        return Response(serializer.data)
    
    serializer = SecuritySettingsSerializer(settings_obj, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save(updated_by=request.user)
        return Response(serializer.data)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([permissions.IsAdminUser])
def system_statistics(request):
    """Estatísticas gerais do sistema"""
    stats = {
        'total_equipments': Equipment.objects.count(),
        'total_configurations': MplsConfiguration.objects.count(),
        'total_vpns': Vpn.objects.count(),
        'total_customers': CustomerService.objects.values('name').distinct().count(),
        'active_equipments': Equipment.objects.filter(status='active').count(),
        'recent_backups': MplsConfiguration.objects.filter(
            backup_date__gte=timezone.now() - timedelta(days=7)
        ).count()
    }
    
    return Response(stats)


# ==========================================
# Endpoints de dashboard
# ==========================================

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def dashboard_overview(request):
    """Dados para dashboard principal"""
    overview = {
        'total_equipments': Equipment.objects.count(),
        'active_equipments': Equipment.objects.filter(status='active').count(),
        'total_vpns': Vpn.objects.count(),
        'total_customers': CustomerService.objects.values('name').distinct().count(),
        'recent_activity': AuditLog.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=24)
        ).count()
    }
    
    return Response(overview)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def recent_activity(request):
    """Atividade recente do sistema"""
    recent_logs = AuditLog.objects.select_related('user').filter(
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).order_by('-timestamp')[:10]
    
    serializer = AuditLogSerializer(recent_logs, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def system_alerts(request):
    """Alertas e notificações do sistema"""
    alerts = []
    
    # Verificar equipamentos sem backup recente
    outdated_equipments = Equipment.objects.filter(
        Q(last_backup__lt=timezone.now() - timedelta(days=7)) | 
        Q(last_backup__isnull=True)
    ).count()
    
    if outdated_equipments > 0:
        alerts.append({
            'type': 'warning',
            'message': f'{outdated_equipments} equipamentos sem backup recente',
            'action': 'process_backups'
        })
    
    return Response({'alerts': alerts})


# ==========================================
# Endpoints de compatibilidade
# ==========================================

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def legacy_search(request):
    """Endpoint de compatibilidade com sistema original"""
    query = request.GET.get('q', '')
    # TODO: Manter compatibilidade total com API original
    return Response({'message': 'Legacy search - TODO', 'query': query})


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def legacy_customer_report(request, customer_name):
    """Relatório de cliente compatível com sistema original"""
    # TODO: Manter formato original de resposta
    return Response({'customer': customer_name, 'message': 'Legacy report - TODO'})


# ==========================================
# Endpoints de manutenção
# ==========================================

@api_view(['POST'])
@permission_classes([permissions.IsAdminUser])
def update_search_vectors(request):
    """Atualizar vetores de busca PostgreSQL"""
    # TODO: Implementar usando search_utils.py
    return Response({'message': 'Search vectors update - TODO'})


@api_view(['POST'])
@permission_classes([permissions.IsAdminUser])
def cleanup_old_logs(request):
    """Limpeza de logs antigos"""
    days = request.data.get('days', 90)
    cutoff_date = timezone.now() - timedelta(days=days)
    
    deleted_access = AccessLog.objects.filter(login_time__lt=cutoff_date).count()
    deleted_audit = AuditLog.objects.filter(timestamp__lt=cutoff_date).count()
    
    AccessLog.objects.filter(login_time__lt=cutoff_date).delete()
    AuditLog.objects.filter(timestamp__lt=cutoff_date).delete()
    
    return Response({
        'message': 'Logs cleaned successfully',
        'deleted_access_logs': deleted_access,
        'deleted_audit_logs': deleted_audit
    })


@api_view(['POST'])
@permission_classes([permissions.IsAdminUser])
def backup_database(request):
    """Backup do banco de dados"""
    # TODO: Implementar backup
    return Response({'message': 'Database backup - TODO'})


# ==========================================
# Endpoints de monitoramento
# ==========================================

@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def health_check(request):
    """Health check do sistema"""
    try:
        # Verificar conectividade com banco
        Equipment.objects.count()
        return Response({
            'status': 'healthy',
            'timestamp': timezone.now(),
            'database': 'connected'
        })
    except Exception as e:
        return Response({
            'status': 'unhealthy',
            'timestamp': timezone.now(),
            'error': str(e)
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def system_metrics(request):
    """Métricas do sistema para monitoramento"""
    metrics = {
        'database': {
            'equipments': Equipment.objects.count(),
            'configurations': MplsConfiguration.objects.count(),
            'vpns': Vpn.objects.count(),
            'customers': CustomerService.objects.values('name').distinct().count()
        },
        'activity': {
            'searches_today': AuditLog.objects.filter(
                action='search',
                timestamp__date=timezone.now().date()
            ).count(),
            'logins_today': AccessLog.objects.filter(
                status='success',
                login_time__date=timezone.now().date()
            ).count()
        },
        'system': {
            'timestamp': timezone.now(),
            'version': '1.0.0'
        }
    }
    
    return Response(metrics)


@require_GET
def network_scan_api(request):
    """API para scan da rede"""
    try:
        from .network_scanner import scan_network_command
        
        username = request.GET.get('username')
        password = request.GET.get('password')
        
        hosts_info = scan_network_command(username, password)
        
        return JsonResponse({
            'success': True,
            'hosts_found': len(hosts_info),
            'hosts': hosts_info
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_GET
def backup_execute_api(request):
    """API para executar backup dos dispositivos"""
    try:
        from .backup_manager import backup_all_devices_command
        
        username = request.GET.get('username')
        password = request.GET.get('password')
        
        success_count, total_count = backup_all_devices_command(username, password)
        
        return JsonResponse({
            'success': True,
            'success_count': success_count,
            'total_count': total_count,
            'message': f'Backup concluído: {success_count}/{total_count} dispositivos'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_GET
def backup_status_api(request):
    """API para verificar status dos backups"""
    try:
        from .backup_manager import get_backup_status_command
        
        status = get_backup_status_command()
        
        return JsonResponse({
            'success': True,
            'status': status
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_GET
def fix_json_api(request):
    """API para corrigir JSONs malformados"""
    try:
        from django.core.management import call_command
        from io import StringIO
        
        # Captura saída do comando
        output = StringIO()
        call_command('fix_malformed_json', stdout=output)
        
        return JsonResponse({
            'success': True,
            'message': 'Correção de JSONs executada',
            'output': output.getvalue()
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
