"""
Views comuns para o app networking - baseado no l2vpn-master
"""
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.http import JsonResponse
from django.contrib.auth.models import User
import logging

from .models import City, NetworkInterface, NetworkConfigurationLog
from .serializers import CitySerializer, NetworkInterfaceSerializer, NetworkConfigurationLogSerializer

logger = logging.getLogger(__name__)


class CityViewSet(viewsets.ModelViewSet):
    """ViewSet para gerenciar cidades - baseado na tabela 'cidades' do l2vpn-master"""
    queryset = City.objects.filter(is_active=True)
    serializer_class = CitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filtrar cidades ativas"""
        return City.objects.filter(is_active=True).order_by('name')


class NetworkInterfaceViewSet(viewsets.ModelViewSet):
    """ViewSet para gerenciar interfaces de rede - baseado na tabela 'interfaces' do l2vpn-master"""
    queryset = NetworkInterface.objects.filter(is_active=True)
    serializer_class = NetworkInterfaceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = super().get_queryset()
        city_id = self.request.query_params.get('city_id', None)
        if city_id:
            queryset = queryset.filter(city__id=city_id)
        return queryset


class NetworkConfigurationLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet para logs de configuração de rede"""
    queryset = NetworkConfigurationLog.objects.all()
    serializer_class = NetworkConfigurationLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filtros opcionais
        operation_type = self.request.query_params.get('operation_type')
        status_filter = self.request.query_params.get('status')
        target_ip = self.request.query_params.get('target_ip')
        
        if operation_type:
            queryset = queryset.filter(operation_type=operation_type)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        if target_ip:
            queryset = queryset.filter(target_ip=target_ip)
            
        return queryset


# ==========================================
# API endpoints específicos (compatibilidade com l2vpn-master)
# ==========================================

@api_view(['GET'])
@permission_classes([AllowAny])
def api_cities(request):
    """
    API compatível com l2vpn-master: /api/cidades
    Retorna lista de cidades no formato esperado pelo frontend original
    """
    cities = City.objects.filter(is_active=True).values('id', 'name', 'ip_address')
    
    # Converter para formato esperado pelo l2vpn-master
    data = [
        {
            'cidadeid': city['id'],
            'nome': city['name'], 
            'ip': city['ip_address']
        }
        for city in cities
    ]
    
    return JsonResponse(data, safe=False)


@api_view(['GET'])
@permission_classes([AllowAny])
def api_interfaces(request):
    """
    API compatível com l2vpn-master: /api/interfaces
    Retorna lista de interfaces no formato esperado pelo frontend original
    """
    interfaces = NetworkInterface.objects.filter(is_active=True).select_related('city')
    
    data = [
        {
            'interfaceid': interface.id,
            'nome': interface.name,
            'cidadeid': interface.city.id,
            'tipo': interface.interface_type
        }
        for interface in interfaces
    ]
    
    return JsonResponse(data, safe=False)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_log_status(request, log_id):
    """
    Obter status do log de execução - compatível com l2vpn-master
    Endpoint: /api/networking/logs/{log_id}/status/
    """
    try:
        log = NetworkConfigurationLog.objects.get(id=log_id)
        return JsonResponse({
            'log_id': str(log.id),
            'status': log.status,
            'operation_type': log.operation_type,
            'target_ip': log.target_ip,
            'username': log.username,
            'commands_executed': log.commands_executed,
            'output': log.output,
            'error_message': log.error_message,
            'execution_time': log.execution_time,
            'started_at': log.started_at.isoformat(),
            'finished_at': log.finished_at.isoformat() if log.finished_at else None,
            'success': log.status == 'success'
        })
    except NetworkConfigurationLog.DoesNotExist:
        return JsonResponse({'error': 'Log não encontrado'}, status=404)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_commit_status(request):
    """
    Status de commit global - compatível com l2vpn-master
    Endpoint: /api/networking/status/commit/
    """
    # Buscar logs recentes para verificar status
    recent_logs = NetworkConfigurationLog.objects.filter(
        operation_type='commit'
    ).order_by('-started_at')[:1]
    
    if recent_logs:
        log = recent_logs[0]
        return JsonResponse({
            'status': log.status,
            'message': log.output or log.error_message or '',
            'commit_duration': log.execution_time,
            'last_commit': log.started_at.isoformat()
        })
    else:
        return JsonResponse({
            'status': 'pending',
            'message': 'Nenhum commit executado recentemente',
            'commit_duration': None,
            'last_commit': None
        })


@api_view(['POST'])
@permission_classes([AllowAny])
def test_connection(request):
    """
    Testar conectividade SSH com um roteador
    Endpoint: /api/networking/test-connection/
    """
    try:
        data = request.data
        
        required_fields = ['host', 'username', 'password']
        for field in required_fields:
            if field not in data:
                return Response(
                    {'error': f'Campo {field} é obrigatório'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Importar classe SSH quando necessário (evitar imports circulares)
        from .ssh_client import SSHNetworkClient
        
        try:
            with SSHNetworkClient(
                data['host'], 
                data['username'], 
                data['password'],
                timeout=10
            ) as client:
                # Comando simples para testar conectividade
                output = client.execute_commands(['show version | head -5'])
                
                return JsonResponse({
                    'success': True,
                    'message': 'Conexão SSH estabelecida com sucesso',
                    'host': data['host'],
                    'test_output': output[:200] + '...' if len(output) > 200 else output
                })
                
        except Exception as ssh_error:
            return JsonResponse({
                'success': False,
                'message': f'Falha na conexão SSH: {str(ssh_error)}',
                'host': data['host'],
                'error': str(ssh_error)
            }, status=400)
            
    except Exception as e:
        logger.error(f"Erro no teste de conexão: {e}", exc_info=True)
        return Response(
            {'error': f'Erro interno: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )