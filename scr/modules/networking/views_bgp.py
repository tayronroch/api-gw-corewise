"""
Views para configurações BGP - baseado no app.py do l2vpn-master
Rota original: /gerar_bgp
"""
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.http import JsonResponse
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.models import User
import json
import logging
import time
import threading
import ipaddress

from .models import BGPConfiguration, NetworkConfigurationLog
from .serializers import BGPConfigurationSerializer

logger = logging.getLogger(__name__)


class BGPConfigurationViewSet(viewsets.ModelViewSet):
    """ViewSet para configurações BGP"""
    queryset = BGPConfiguration.objects.filter(is_active=True)
    serializer_class = BGPConfigurationSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def execute(self, request, pk=None):
        """
        Executa configuração BGP no roteador
        Baseado na rota /gerar_bgp do l2vpn-master
        """
        config = self.get_object()
        
        # Validar dados de login
        login_data = request.data
        if not login_data.get('username') or not login_data.get('password'):
            return Response(
                {'error': 'Username e password são obrigatórios'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Criar log de execução
        log = NetworkConfigurationLog.objects.create(
            operation_type='bgp',
            status='running',
            target_ip=config.router_ip,
            username=login_data['username'],
            created_by=request.user,
            bgp_config=config
        )
        
        try:
            # Executar configuração em thread separada
            thread = threading.Thread(
                target=self._execute_bgp_config,
                args=(config, login_data, log),
                name=f"BGP-{config.id}"
            )
            thread.daemon = True
            thread.start()
            
            return Response({
                'message': 'Configuração BGP iniciada',
                'log_id': str(log.id),
                'config_id': str(config.id),
                'router_ip': config.router_ip,
                'client_name': config.client_name
            })
            
        except Exception as e:
            log.status = 'failed'
            log.error_message = str(e)
            log.finished_at = timezone.now()
            log.save()
            
            return Response(
                {'error': f'Erro ao iniciar configuração BGP: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _execute_bgp_config(self, config: BGPConfiguration, login_data: dict, log: NetworkConfigurationLog):
        """
        Executa configuração BGP em background
        Replicação da lógica do l2vpn-master
        """
        start_time = time.time()
        
        try:
            logger.info(f"Iniciando configuração BGP {config.id} para {config.client_name}")
            
            # Gerar comandos BGP
            from .command_generators import BGPCommandGenerator
            cmd_generator = BGPCommandGenerator()
            bgp_commands = cmd_generator.generate_bgp_commands(config)
            
            logger.info(f"Comandos BGP gerados: {len(bgp_commands)} comandos")
            
            # Salvar comandos no log
            log.commands_executed = bgp_commands
            log.save()
            
            # Executar comandos
            result = self._execute_ssh_commands(
                config.router_ip,
                login_data['username'],
                login_data['password'],
                bgp_commands
            )
            
            # Processar resultado
            log.status = 'success' if result['success'] else 'failed'
            log.output = result['output']
            
            if not result['success']:
                log.error_message = result.get('error')
            
            logger.info(f"Configuração BGP {config.id} finalizada - Status: {log.status}")
            
        except Exception as e:
            log.status = 'failed'
            log.error_message = f"Erro na execução BGP: {str(e)}"
            logger.error(f"Erro na execução BGP {config.id}: {e}", exc_info=True)
            
        finally:
            log.execution_time = time.time() - start_time
            log.finished_at = timezone.now()
            log.save()

    def _execute_ssh_commands(self, host_ip: str, username: str, password: str, commands: list) -> dict:
        """Executa comandos SSH em um host"""
        try:
            logger.info(f"Conectando SSH em {host_ip} para configuração BGP")
            
            from .ssh_client import SSHNetworkClient
            
            with SSHNetworkClient(host_ip, username, password, timeout=30) as client:
                output = client.execute_commands(commands)
                
                logger.info(f"Comandos BGP executados com sucesso em {host_ip}")
                return {
                    'success': True,
                    'output': output,
                    'host': host_ip
                }
                
        except Exception as e:
            logger.error(f"Erro SSH BGP em {host_ip}: {e}")
            return {
                'success': False,
                'error': str(e),
                'output': '',
                'host': host_ip
            }


# ==========================================
# Funções auxiliares do l2vpn-master
# ==========================================

def validar_numerico(valor: str, campo: str) -> bool:
    """Validação numérica como no l2vpn-master"""
    try:
        int(valor)
        return True
    except ValueError:
        logger.warning(f"Campo {campo} deve ser numérico: {valor}")
        return False


def calcular_ips(subnet: str) -> tuple:
    """
    Calcula IPs da subnet como no l2vpn-master
    Retorna (ip_local, ip_peer)
    """
    try:
        network = ipaddress.IPv4Network(subnet, strict=False) if ':' not in subnet else ipaddress.IPv6Network(subnet, strict=False)
        hosts = list(network.hosts())
        if len(hosts) >= 2:
            return str(hosts[0]), str(hosts[1])
        else:
            raise ValueError("Subnet deve ter pelo menos 2 hosts disponíveis")
    except Exception as e:
        logger.error(f"Erro ao calcular IPs da subnet {subnet}: {e}")
        raise


# ==========================================
# API endpoint compatível com l2vpn-master
# ==========================================

@api_view(['GET', 'POST'])
@permission_classes([AllowAny])  # Compatibilidade
def gerar_bgp(request):
    """
    Endpoint compatível com l2vpn-master: /gerar_bgp
    Processa dados do formulário BGP original
    """
    if request.method == 'GET':
        # Retornar template ou dados para formulário
        return JsonResponse({
            'message': 'Endpoint BGP ativo',
            'method': 'POST',
            'required_fields': [
                'ip_roteador', 'login', 'senha', 'vlan', 'cliente',
                'subnet_v4', 'subnet_v6', 'asn_cliente', 
                'rede_v4_cliente', 'rede_v6_cliente', 
                'tamanho_v4', 'tamanho_v6'
            ]
        })
    
    try:
        data = request.data
        
        # Validar campos obrigatórios (baseado no l2vpn-master)
        campos_requeridos = {
            'ip_roteador': 'IP do Roteador',
            'login': 'Login',
            'senha': 'Senha',
            'vlan': 'VLAN',
            'cliente': 'Cliente',
            'subnet_v4': 'Subnet IPv4',
            'subnet_v6': 'Subnet IPv6',
            'asn_cliente': 'ASN do Cliente',
            'rede_v4_cliente': 'Rede IPv4',
            'rede_v6_cliente': 'Rede IPv6',
            'tamanho_v4': 'Tamanho IPv4',
            'tamanho_v6': 'Tamanho IPv6',
        }
        
        dados = {k: data.get(k, '').strip() for k in campos_requeridos}
        
        # Validação básica
        missing_fields = []
        for campo, nome in campos_requeridos.items():
            if not dados[campo]:
                missing_fields.append(nome)
                
        if missing_fields:
            return Response(
                {'error': f'Campos obrigatórios: {", ".join(missing_fields)}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validar campos numéricos
        numeric_fields = ['asn_cliente', 'tamanho_v4', 'tamanho_v6']
        for field in numeric_fields:
            if not validar_numerico(dados[field], field):
                return Response(
                    {'error': f'Campo {field} deve ser numérico'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        try:
            # Validar e calcular redes (lógica do l2vpn-master)
            network_v4 = ipaddress.IPv4Network(dados['rede_v4_cliente'], strict=False)
            network_v6 = ipaddress.IPv6Network(dados['rede_v6_cliente'], strict=False)
            v4_ips = calcular_ips(dados['subnet_v4'])
            v6_ips = calcular_ips(dados['subnet_v6'])
            
        except Exception as e:
            return Response(
                {'error': f'Erro na validação de redes: {str(e)}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Criar configuração BGP
        config_data = {
            'router_ip': dados['ip_roteador'],
            'vlan': dados['vlan'],
            'client_name': dados['cliente'],
            'subnet_v4': dados['subnet_v4'],
            'client_network_v4': dados['rede_v4_cliente'],
            'v4_size': int(dados['tamanho_v4']),
            'subnet_v6': dados['subnet_v6'],
            'client_network_v6': dados['rede_v6_cliente'],
            'v6_size': int(dados['tamanho_v6']),
            'client_asn': int(dados['asn_cliente']),
            'created_by': request.user if request.user.is_authenticated else User.objects.get(username='admin'),
            'description': f"BGP configurado via API compatível para {dados['cliente']} - {timezone.now()}"
        }
        
        # Criar e executar configuração
        with transaction.atomic():
            config = BGPConfiguration.objects.create(**config_data)
            
            # Usar ViewSet para executar
            viewset = BGPConfigurationViewSet()
            response_data = viewset.execute(
                type('Request', (), {
                    'data': {'username': dados['login'], 'password': dados['senha']},
                    'user': request.user if request.user.is_authenticated else User.objects.get(username='admin')
                })(),
                pk=config.id
            )
        
        return Response({
            'success': True,
            'message': 'Configuração BGP iniciada com sucesso',
            'config_id': str(config.id),
            'log_id': response_data.data.get('log_id'),
            'client_name': config.client_name,
            'router_ip': config.router_ip,
            'client_asn': config.client_asn,
            'calculated_data': {
                'v4_ip_local': v4_ips[0],
                'v4_ip_peer': v4_ips[1],
                'v6_ip_local': v6_ips[0],
                'v6_ip_peer': v6_ips[1],
                'v4_network': str(network_v4.network_address),
                'v4_prefix': str(network_v4.prefixlen),
                'v6_network': str(network_v6.network_address).upper(),
                'v6_prefix': str(network_v6.prefixlen)
            }
        })
        
    except Exception as e:
        logger.error(f"Erro na configuração BGP compatível: {e}", exc_info=True)
        return Response(
            {'error': f'Erro interno: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )