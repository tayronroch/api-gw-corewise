"""
Views para configurações OSPF
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
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import OSPFConfiguration, NetworkConfigurationLog
from .serializers import OSPFConfigurationSerializer

logger = logging.getLogger(__name__)


class OSPFConfigurationViewSet(viewsets.ModelViewSet):
    queryset = OSPFConfiguration.objects.filter(is_active=True)
    serializer_class = OSPFConfigurationSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['post'])
    def execute(self, request, pk=None):
        """
        Executa configuração OSPF no roteador
        Baseado na rota /executar_config_ospf do l2vpn-master
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
            operation_type='ospf',
            status='running',
            target_ip=config.router_ip,
            username=login_data['username'],
            created_by=request.user,
            ospf_config=config
        )
        
        try:
            # Executar configuração em thread separada
            thread = threading.Thread(
                target=self._execute_ospf_config,
                args=(config, login_data, log),
                name=f"OSPF-{config.id}"
            )
            thread.daemon = True
            thread.start()
            
            return Response({
                'message': 'Configuração OSPF iniciada',
                'log_id': str(log.id),
                'config_id': str(config.id),
                'router_ip': config.router_ip,
                'router_id': config.router_id
            })
            
        except Exception as e:
            log.status = 'failed'
            log.error_message = str(e)
            log.finished_at = timezone.now()
            log.save()
            
            return Response(
                {'error': f'Erro ao iniciar configuração OSPF: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _execute_ospf_config(self, config: OSPFConfiguration, login_data: dict, log: NetworkConfigurationLog):
        """
        Executa configuração OSPF em background
        Replicação da lógica do l2vpn-master
        """
        start_time = time.time()
        
        try:
            logger.info(f"Iniciando configuração OSPF {config.id} - Router ID: {config.router_id}")
            
            # Gerar comandos OSPF
            from .command_generators import OSPFCommandGenerator
            cmd_generator = OSPFCommandGenerator()
            ospf_commands = cmd_generator.generate_ospf_commands(config)
            
            logger.info(f"Comandos OSPF gerados: {len(ospf_commands)} comandos")
            
            # Salvar comandos no log
            log.commands_executed = ospf_commands
            log.save()
            
            # Executar comandos
            result = self._execute_ssh_commands(
                config.router_ip,
                login_data['username'],
                login_data['password'],
                ospf_commands
            )
            
            # Processar resultado
            log.status = 'success' if result['success'] else 'failed'
            log.output = result['output']
            
            if not result['success']:
                log.error_message = result.get('error')
            
            logger.info(f"Configuração OSPF {config.id} finalizada - Status: {log.status}")
            
        except Exception as e:
            log.status = 'failed'
            log.error_message = f"Erro na execução OSPF: {str(e)}"
            logger.error(f"Erro na execução OSPF {config.id}: {e}", exc_info=True)
            
        finally:
            log.execution_time = time.time() - start_time
            log.finished_at = timezone.now()
            log.save()

    def _execute_ssh_commands(self, host_ip: str, username: str, password: str, commands: list) -> dict:
        """Executa comandos SSH em um host"""
        try:
            logger.info(f"Conectando SSH em {host_ip} para configuração OSPF")
            
            from .ssh_client import SSHNetworkClient
            
            with SSHNetworkClient(host_ip, username, password, timeout=30) as client:
                output = client.execute_commands(commands)
                
                logger.info(f"Comandos OSPF executados com sucesso em {host_ip}")
                return {
                    'success': True,
                    'output': output,
                    'host': host_ip
                }
                
        except Exception as e:
            logger.error(f"Erro SSH OSPF em {host_ip}: {e}")
            return {
                'success': False,
                'error': str(e),
                'output': '',
                'host': host_ip
            }


# ==========================================
# API endpoint compatível com l2vpn-master
# ==========================================

@api_view(['POST'])
@permission_classes([AllowAny])  # Compatibilidade
def executar_config_ospf(request):
    """
    Endpoint compatível com l2vpn-master: /executar_config_ospf
    Processa configurações OSPF em lote (múltiplos roteadores)
    """
    try:
        data = request.data
        
        logger.info("Dados recebidos no endpoint '/executar_config_ospf'")
        logger.debug(f"Dados OSPF: {json.dumps(data, indent=2)}")
        
        # Validar estrutura de dados
        if not data or 'login' not in data or 'senha' not in data or 'configs' not in data:
            logger.error("Dados inválidos recebidos no endpoint '/executar_config_ospf'")
            return Response({
                'error': 'Dados inválidos. Campos obrigatórios: login, senha, configs'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        login = data['login']
        senha = data['senha']
        configs = data['configs']
        
        if not configs or not isinstance(configs, list):
            logger.error("Nenhuma configuração fornecida ou formato inválido")
            return Response({
                'error': 'Nenhuma configuração fornecida ou configs deve ser uma lista'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Agrupar configurações por IP (como no l2vpn-master)
        grouped_by_ip = defaultdict(list)
        for cfg in configs:
            ip = cfg.get('ip')
            if not ip:
                logger.error(f"Configuração sem campo 'ip': {cfg}")
                return Response({
                    'error': f'Configuração inválida (sem IP): {cfg}'
                }, status=status.HTTP_400_BAD_REQUEST)
            grouped_by_ip[ip].append(cfg)
        
        all_results = []
        created_configs = []
        
        # Processar cada roteador
        with ThreadPoolExecutor(max_workers=5, thread_name_prefix="OSPF-Multi") as executor:
            future_to_ip = {}
            
            for router_ip, router_configs in grouped_by_ip.items():
                # Criar configurações OSPF para cada roteador
                for cfg in router_configs:
                    try:
                        config_data = {
                            'router_ip': router_ip,
                            'process_id': cfg.get('process_id', 1),
                            'router_id': cfg.get('router_id', router_ip),
                            'area_id': cfg.get('area_id', '0'),
                            'interface': cfg.get('interface', 'loopback-0'),
                            'cost': cfg.get('cost', 100),
                            'created_by': request.user if request.user.is_authenticated else User.objects.get(username='admin'),
                            'description': f"OSPF configurado via API compatível - Lote {timezone.now()}"
                        }
                        
                        ospf_config = OSPFConfiguration.objects.create(**config_data)
                        created_configs.append(ospf_config)
                        
                    except Exception as e:
                        logger.error(f"Erro ao criar configuração OSPF para {router_ip}: {e}")
                        return Response({
                            'error': f'Erro ao criar configuração para {router_ip}: {str(e)}'
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                # Submeter tarefa para executar em paralelo
                future = executor.submit(
                    execute_ospf_for_router,
                    router_ip, 
                    router_configs,
                    login,
                    senha,
                    request.user if request.user.is_authenticated else User.objects.get(username='admin')
                )
                future_to_ip[future] = router_ip
            
            # Coletar resultados
            for future in as_completed(future_to_ip):
                router_ip = future_to_ip[future]
                try:
                    result = future.result(timeout=300)  # 5 minutos timeout
                    result['router_ip'] = router_ip
                    all_results.append(result)
                    
                except Exception as e:
                    logger.error(f"Erro na execução OSPF para {router_ip}: {e}")
                    all_results.append({
                        'router_ip': router_ip,
                        'success': False,
                        'error': str(e),
                        'output': ''
                    })
        
        # Processar resultados finais
        successful_configs = [r for r in all_results if r.get('success', False)]
        failed_configs = [r for r in all_results if not r.get('success', False)]
        
        return Response({
            'success': len(failed_configs) == 0,
            'message': f'Processamento concluído: {len(successful_configs)} sucessos, {len(failed_configs)} falhas',
            'total_configs': len(all_results),
            'successful_configs': len(successful_configs),
            'failed_configs': len(failed_configs),
            'results': all_results,
            'created_config_ids': [str(cfg.id) for cfg in created_configs]
        })
        
    except Exception as e:
        logger.error(f"Erro no processamento OSPF em lote: {e}", exc_info=True)
        return Response(
            {'error': f'Erro interno: {str(e)}'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


def execute_ospf_for_router(router_ip: str, configs: list, username: str, password: str, user: User) -> dict:
    """
    Executa configurações OSPF para um roteador específico
    Função auxiliar para processamento em paralelo
    """
    try:
        logger.info(f"Executando configurações OSPF para roteador {router_ip}")
        
        # Criar log para este roteador
        log = NetworkConfigurationLog.objects.create(
            operation_type='ospf',
            status='running',
            target_ip=router_ip,
            username=username,
            created_by=user
        )
        
        # Gerar todos os comandos para este roteador
        from .command_generators import OSPFCommandGenerator
        cmd_generator = OSPFCommandGenerator()
        
        all_commands = []
        for cfg in configs:
            # Simular configuração OSPF temporária para gerar comandos
            temp_config = type('OSPFConfig', (), {
                'router_ip': router_ip,
                'process_id': cfg.get('process_id', 1),
                'router_id': cfg.get('router_id', router_ip),
                'area_id': cfg.get('area_id', '0'),
                'interface': cfg.get('interface', 'loopback-0'),
                'cost': cfg.get('cost', 100)
            })()
            
            commands = cmd_generator.generate_ospf_commands(temp_config)
            all_commands.extend(commands)
        
        # Salvar comandos no log
        log.commands_executed = all_commands
        log.save()
        
        # Executar comandos SSH
        from .ssh_client import SSHNetworkClient
        
        with SSHNetworkClient(router_ip, username, password, timeout=60) as client:
            output = client.execute_commands(all_commands)
            
            # Atualizar log
            log.status = 'success'
            log.output = output
            log.finished_at = timezone.now()
            log.save()
            
            logger.info(f"Configurações OSPF executadas com sucesso em {router_ip}")
            return {
                'success': True,
                'output': output,
                'log_id': str(log.id),
                'configs_count': len(configs)
            }
            
    except Exception as e:
        logger.error(f"Erro na execução OSPF para {router_ip}: {e}")
        
        # Atualizar log com erro
        if 'log' in locals():
            log.status = 'failed'
            log.error_message = str(e)
            log.finished_at = timezone.now()
            log.save()
            
        return {
            'success': False,
            'error': str(e),
            'output': '',
            'log_id': str(log.id) if 'log' in locals() else None
        }


@api_view(['GET'])
@permission_classes([AllowAny])
def config_ospf_page(request):
    """
    Endpoint compatível para página de configuração OSPF
    Rota original: /Config_OSPF
    """
    # Retornar dados necessários para formulário OSPF
    return JsonResponse({
        'message': 'Página de configuração OSPF',
        'endpoints': {
            'execute': '/api/networking/ospf/execute/',
            'configs': '/api/networking/ospf/',
            'logs': '/api/networking/logs/'
        },
        'default_values': {
            'process_id': 1,
            'area_id': '0',
            'cost': 100
        }
    })