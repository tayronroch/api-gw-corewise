"""
Views para configurações L2VPN - baseado no app.py do l2vpn-master
Rota original: /configure_l2vpn
"""
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.http import JsonResponse
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
import json
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from .models import City, L2VPNConfiguration, NetworkConfigurationLog
from .serializers import L2VPNConfigurationSerializer

logger = logging.getLogger(__name__)


class L2VPNConfigurationViewSet(viewsets.ModelViewSet):
    """ViewSet para configurações L2VPN VPWS"""
    queryset = L2VPNConfiguration.objects.filter(is_active=True)
    serializer_class = L2VPNConfigurationSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def execute(self, request, pk=None):
        """
        Executa configuração L2VPN nos dispositivos PE1 e PE2
        Baseado na rota /configure_l2vpn do l2vpn-master
        """
        config = self.get_object()
        
        # Validar dados de login
        login_data = request.data
        if not login_data.get('username') or not login_data.get('password'):
            return Response(
                {'error': 'Username e password são obrigatórios'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validar que PE1 e PE2 são diferentes
        if config.pe1_city.id == config.pe2_city.id:
            return Response(
                {'error': 'As cidades PE1 e PE2 devem ser diferentes'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Criar log de execução
        log = NetworkConfigurationLog.objects.create(
            operation_type='l2vpn',
            status='running',
            username=login_data['username'],
            created_by=request.user,
            l2vpn_config=config
        )
        
        try:
            # Executar configuração em thread separada para não bloquear API
            thread = threading.Thread(
                target=self._execute_l2vpn_config,
                args=(config, login_data, log),
                name=f"L2VPN-{config.id}"
            )
            thread.daemon = True
            thread.start()
            
            return Response({
                'message': 'Configuração L2VPN iniciada',
                'log_id': str(log.id),
                'config_id': str(config.id),
                'pe1_city': config.pe1_city.name,
                'pe2_city': config.pe2_city.name
            })
            
        except Exception as e:
            log.status = 'failed'
            log.error_message = str(e)
            log.finished_at = timezone.now()
            log.save()
            
            return Response(
                {'error': f'Erro ao iniciar configuração: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _execute_l2vpn_config(self, config: L2VPNConfiguration, login_data: dict, log: NetworkConfigurationLog):
        """
        Executa configuração L2VPN em background
        Replicação da lógica do l2vpn-master
        """
        start_time = time.time()
        
        try:
            logger.info(f"Iniciando configuração L2VPN {config.id}")
            
            # Gerar comandos para PE1 e PE2
            from .command_generators import L2VPNCommandGenerator
            cmd_generator = L2VPNCommandGenerator()
            
            pe1_commands = cmd_generator.generate_pe_commands(config, 'pe1')
            pe2_commands = cmd_generator.generate_pe_commands(config, 'pe2')
            
            logger.info(f"Comandos gerados - PE1 e PE2")
            
            # Salvar comandos no log
            log.commands_executed = {
                'pe1_commands': pe1_commands,
                'pe2_commands': pe2_commands,
                'pe1_ip': config.pe1_city.ip_address,
                'pe2_ip': config.pe2_city.ip_address
            }
            log.save()
            
            # Executar comandos nos dois PEs em paralelo (como no l2vpn-master)
            with ThreadPoolExecutor(max_workers=2, thread_name_prefix="L2VPN-PE") as executor:
                # Submeter tarefas para cada PE
                future_pe1 = executor.submit(
                    self._execute_ssh_commands,
                    config.pe1_city.ip_address,
                    login_data['username'],
                    login_data['password'],
                    pe1_commands,
                    f"PE1-{config.pe1_city.name}"
                )
                
                future_pe2 = executor.submit(
                    self._execute_ssh_commands,
                    config.pe2_city.ip_address,
                    login_data['username'],
                    login_data['password'],
                    pe2_commands,
                    f"PE2-{config.pe2_city.name}"
                )
                
                # Aguardar resultados
                pe1_result = future_pe1.result(timeout=300)  # 5 minutos timeout
                pe2_result = future_pe2.result(timeout=300)
            
            # Processar resultados
            success = pe1_result['success'] and pe2_result['success']
            
            log.status = 'success' if success else 'failed'
            log.output = json.dumps({
                'pe1_output': pe1_result['output'],
                'pe2_output': pe2_result['output'],
                'pe1_success': pe1_result['success'],
                'pe2_success': pe2_result['success']
            }, ensure_ascii=False, indent=2)
            
            if not success:
                errors = {}
                if not pe1_result['success']:
                    errors['pe1_error'] = pe1_result.get('error')
                if not pe2_result['success']:
                    errors['pe2_error'] = pe2_result.get('error')
                    
                log.error_message = json.dumps(errors, ensure_ascii=False, indent=2)
            
            logger.info(f"Configuração L2VPN {config.id} finalizada - Status: {log.status}")
            
        except Exception as e:
            log.status = 'failed'
            log.error_message = f"Erro na execução L2VPN: {str(e)}"
            logger.error(f"Erro na execução L2VPN {config.id}: {e}", exc_info=True)
            
        finally:
            log.execution_time = time.time() - start_time
            log.finished_at = timezone.now()
            log.save()

    def _execute_ssh_commands(self, host_ip: str, username: str, password: str, commands: list, pe_name: str = "") -> dict:
        """
        Executa comandos SSH em um host específico
        Baseado na lógica do utils.py do l2vpn-master
        """
        try:
            logger.info(f"Conectando SSH em {pe_name} ({host_ip})")
            
            # Importar cliente SSH
            from .ssh_client import SSHNetworkClient
            
            with SSHNetworkClient(host_ip, username, password, timeout=30) as client:
                output = client.execute_commands(commands)
                
                logger.info(f"Comandos executados com sucesso em {pe_name}")
                return {
                    'success': True,
                    'output': output,
                    'host': host_ip,
                    'pe_name': pe_name
                }
                
        except Exception as e:
            logger.error(f"Erro SSH em {pe_name} ({host_ip}): {e}")
            return {
                'success': False,
                'error': str(e),
                'output': '',
                'host': host_ip,
                'pe_name': pe_name
            }


# ==========================================
# API endpoint compatível com l2vpn-master
# ==========================================

@api_view(['POST'])
@permission_classes([AllowAny])  # Compatibilidade com frontend original
def configure_l2vpn(request):
    """
    Endpoint compatível com l2vpn-master: /configure_l2vpn
    Processa dados do formulário HTML original e executa configuração L2VPN
    """
    try:
        data = request.data
        
        # Validar dados obrigatórios (baseado no l2vpn-master)
        required_fields = [
            'cidade_pe1', 'cidade_pe2', 'login', 'senha',
            'vpws_group_name_pe1', 'vpn_id_pe1', 'neighbor_ip_pe1', 'pw_id_pe1',
            'vpws_group_name_pe2', 'vpn_id_pe2', 'neighbor_ip_pe2', 'pw_id_pe2',
            'neighbor_targeted_ip_pe1', 'neighbor_targeted_ip_pe2'
        ]
        
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return Response(
                {'error': f'Campos obrigatórios: {", ".join(missing_fields)}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validar que cidades são diferentes
        if data['cidade_pe1'] == data['cidade_pe2']:
            return Response(
                {'error': 'As cidades PE1 e PE2 devem ser diferentes'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Buscar cidades
        try:
            pe1_city = City.objects.get(name=data['cidade_pe1'])
            pe2_city = City.objects.get(name=data['cidade_pe2'])
        except City.DoesNotExist as e:
            return Response(
                {'error': f'Cidade não encontrada: {str(e)}'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Determinar modos L2VPN (baseado nos checkboxes do frontend)
        pe1_mode = 'qinq'  # padrão
        pe2_mode = 'qinq'  # padrão
        
        if data.get('access_pe1') == 'access':
            pe1_mode = 'access'
        elif data.get('vlan_selective_pe1') == 'vlan-selective':
            pe1_mode = 'vlan-selective'
            
        if data.get('access_pe2') == 'access':
            pe2_mode = 'access'
        elif data.get('vlan_selective_pe2') == 'vlan-selective':
            pe2_mode = 'vlan-selective'
        
        # Montar interfaces (lógica do l2vpn-master)
        def build_interface(empresa, numero):
            if empresa and empresa.strip().lower() == "lag-":
                return f"lag-{numero}"
            else:
                return f"{empresa}-ethernet-1/1/{numero}"
        
        pe1_interface = build_interface(data.get('empresa_pe1'), data.get('numero_pe1'))
        pe2_interface = build_interface(data.get('empresa_pe2'), data.get('numero_pe2'))
        
        # Criar configuração L2VPN
        config_data = {
            'pe1_city': pe1_city,
            'pe2_city': pe2_city,
            'pe1_mode': pe1_mode,
            'pe2_mode': pe2_mode,
            'pe1_vpws_group_name': data['vpws_group_name_pe1'],
            'pe1_vpn_id': data['vpn_id_pe1'],
            'pe1_neighbor_ip': data['neighbor_ip_pe1'],
            'pe1_pw_id': data['pw_id_pe1'],
            'pe1_access_interface': pe1_interface,
            'pe1_dot1q': data.get('dot1q_pe1', ''),
            'pe1_pw_vlan': data.get('pw_vlan_pe1', ''),
            'pe1_neighbor_targeted_ip': data['neighbor_targeted_ip_pe1'],
            'pe2_vpws_group_name': data['vpws_group_name_pe2'],
            'pe2_vpn_id': data['vpn_id_pe2'],
            'pe2_neighbor_ip': data['neighbor_ip_pe2'],
            'pe2_pw_id': data['pw_id_pe2'],
            'pe2_access_interface': pe2_interface,
            'pe2_dot1q': data.get('dot1q_pe2', ''),
            'pe2_pw_vlan': data.get('pw_vlan_pe2', ''),
            'pe2_neighbor_targeted_ip': data['neighbor_targeted_ip_pe2'],
            'created_by': request.user if request.user.is_authenticated else User.objects.get(username='admin'),
            'description': f"L2VPN configurado via API compatível - {timezone.now()}"
        }
        
        # Criar e executar configuração
        with transaction.atomic():
            config = L2VPNConfiguration.objects.create(**config_data)
            
            # Usar ViewSet para executar
            viewset = L2VPNConfigurationViewSet()
            response_data = viewset.execute(
                type('Request', (), {
                    'data': {'username': data['login'], 'password': data['senha']},
                    'user': request.user if request.user.is_authenticated else User.objects.get(username='admin')
                })(),
                pk=config.id
            )
        
        return Response({
            'success': True,
            'message': 'Configuração L2VPN iniciada com sucesso',
            'config_id': str(config.id),
            'log_id': response_data.data.get('log_id'),
            'pe1_city': pe1_city.name,
            'pe2_city': pe2_city.name,
            'pe1_mode': pe1_mode,
            'pe2_mode': pe2_mode
        })
        
    except Exception as e:
        logger.error(f"Erro na configuração L2VPN compatível: {e}", exc_info=True)
        return Response(
            {'error': f'Erro interno: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )