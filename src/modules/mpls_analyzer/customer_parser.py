"""
Parser para extrair dados de clientes dos JSONs DMOS e popular CustomerIndex
"""
import re
import json
import logging
from typing import Dict, List, Set, Any, Optional
from django.utils import timezone
from .models import CustomerIndex

logger = logging.getLogger(__name__)


class CustomerNameExtractor:
    """Extrator de nomes de clientes dos JSONs DMOS"""
    
    def __init__(self):
        # Padrões para identificar nomes de clientes
        self.client_patterns = [
            # Padrões comuns em descrições
            r'(?i)cliente[:\s-]+([^,\n\r\|]+)',  # "CLIENTE: Nome"
            r'(?i)customer[:\s-]+([^,\n\r\|]+)',  # "CUSTOMER: Nome"
            r'(?i)cli[:\s-]+([^,\n\r\|]+)',      # "CLI: Nome"
            
            # Nomes de grupos VPWS (removendo prefixos técnicos)
            r'^([A-Z][A-Z0-9\-\s]+?)(?:-PE\d+|-CE\d+|$)',  # Remove sufixos de equipamento
            
            # Descrições de LAG e interface
            r'(?i)([A-Z][A-Z0-9\-\s]{3,}?)(?:-WAN|-LAN|-INTERNET|-VOICE|-DATA|-MPLS)',
            
            # Padrões específicos de ISP/provedor
            r'(?i)ISP[:\s-]+([^,\n\r\|]+)',
            r'(?i)PROVEDOR[:\s-]+([^,\n\r\|]+)',
        ]
        
        # Palavras para filtrar (não são nomes de clientes)
        self.exclude_words = {
            'interface', 'lag', 'gigabit', 'ethernet', 'hundred', 'ten',
            'pe01', 'pe02', 'pe03', 'ce01', 'ce02', 'ce03',
            'wan', 'lan', 'internet', 'voice', 'data', 'mpls',
            'vlan', 'dot1q', 'qinq', 'encapsulation',
            'neighbor', 'pw', 'vpws', 'vpn', 'group',
            'config', 'management', 'loopback', 'null'
        }
        
        # Cache de nomes limpos
        self._name_cache = {}
    
    def extract_from_json(self, json_data: Dict[str, Any], equipment_name: str, source_file: str = "") -> Dict[str, List[Dict]]:
        """
        Extrai todos os nomes de clientes de um JSON DMOS
        
        Returns:
            Dict com nomes de clientes e suas ocorrências
        """
        clients = {}
        
        try:
            data = json_data.get('data', {})
            
            # 1. Extrair de LAGs (Link Aggregation)
            lag_clients = self._extract_from_lags(data, equipment_name, source_file)
            self._merge_clients(clients, lag_clients)
            
            # 2. Extrair de grupos VPWS  
            vpws_clients = self._extract_from_vpws_groups(data, equipment_name, source_file)
            self._merge_clients(clients, vpws_clients)
            
            # 3. Extrair de descrições de VPN
            vpn_clients = self._extract_from_vpn_descriptions(data, equipment_name, source_file)
            self._merge_clients(clients, vpn_clients)
            
            # 4. Extrair de interfaces físicas (se houver)
            interface_clients = self._extract_from_interfaces(data, equipment_name, source_file)
            self._merge_clients(clients, interface_clients)
            
        except Exception as e:
            logger.error(f"Erro ao extrair clientes de {equipment_name}: {e}")
        
        return clients
    
    def _extract_from_lags(self, data: Dict, equipment_name: str, source_file: str) -> Dict:
        """Extrai nomes de clientes das descrições de LAGs"""
        clients = {}
        
        try:
            link_agg = data.get('lacp:link-aggregation', {})
            interface_data = link_agg.get('interface', {})
            lags = interface_data.get('lag', [])
            
            for lag in lags:
                lag_id = lag.get('lag-id')
                lag_config = lag.get('interface-lag-config', {})
                description = lag_config.get('description', '').strip()
                
                if description and len(description) > 3:
                    # Extrair nomes da descrição
                    extracted_names = self._extract_names_from_text(description)
                    
                    for name in extracted_names:
                        if name not in clients:
                            clients[name] = []
                        
                        clients[name].append({
                            'equipment': equipment_name,
                            'context_type': 'lag_description',
                            'interface': f'lag-{lag_id}',
                            'description': description,
                            'vpn_id': None,
                            'source_file': source_file
                        })
        
        except Exception as e:
            logger.error(f"Erro ao extrair de LAGs: {e}")
        
        return clients
    
    def _extract_from_vpws_groups(self, data: Dict, equipment_name: str, source_file: str) -> Dict:
        """Extrai nomes de clientes dos nomes dos grupos VPWS"""
        clients = {}
        
        try:
            l2vpn_config = data.get('l2-vpn:l2vpn-config', {})
            l2vpn = l2vpn_config.get('l2vpn', {})
            vpws_groups = l2vpn.get('vpws-group', [])
            
            for group in vpws_groups:
                group_name = group.get('group-name', '').strip()
                
                if group_name and len(group_name) > 3:
                    # Extrair nomes do nome do grupo
                    extracted_names = self._extract_names_from_text(group_name)
                    
                    # Pegar VPNs do grupo
                    vpns = group.get('vpn', [])
                    vpn_ids = [vpn.get('vpn-name') for vpn in vpns if vpn.get('vpn-name')]
                    
                    for name in extracted_names:
                        if name not in clients:
                            clients[name] = []
                        
                        for vpn_id in vpn_ids:
                            clients[name].append({
                                'equipment': equipment_name,
                                'context_type': 'vpws_group_name',
                                'interface': None,
                                'description': group_name,
                                'vpn_id': vpn_id,
                                'source_file': source_file
                            })
        
        except Exception as e:
            logger.error(f"Erro ao extrair de grupos VPWS: {e}")
        
        return clients
    
    def _extract_from_vpn_descriptions(self, data: Dict, equipment_name: str, source_file: str) -> Dict:
        """Extrai nomes de clientes das descrições específicas de VPNs"""
        clients = {}
        
        try:
            l2vpn_config = data.get('l2-vpn:l2vpn-config', {})
            l2vpn = l2vpn_config.get('l2vpn', {})
            vpws_groups = l2vpn.get('vpws-group', [])
            
            for group in vpws_groups:
                vpns = group.get('vpn', [])
                
                for vpn in vpns:
                    vpn_id = vpn.get('vpn-name')
                    vpn_description = vpn.get('description', '').strip()
                    
                    if vpn_description and len(vpn_description) > 3:
                        extracted_names = self._extract_names_from_text(vpn_description)
                        
                        for name in extracted_names:
                            if name not in clients:
                                clients[name] = []
                            
                            clients[name].append({
                                'equipment': equipment_name,
                                'context_type': 'vpn_description',
                                'interface': None,
                                'description': vpn_description,
                                'vpn_id': vpn_id,
                                'source_file': source_file
                            })
        
        except Exception as e:
            logger.error(f"Erro ao extrair de descrições VPN: {e}")
        
        return clients
    
    def _extract_from_interfaces(self, data: Dict, equipment_name: str, source_file: str) -> Dict:
        """Extrai nomes de clientes de descrições de interfaces físicas (se existirem)"""
        clients = {}
        
        # TODO: Implementar se houver descrições em interfaces físicas no JSON
        # Por enquanto, as descrições principais estão em LAGs e grupos VPWS
        
        return clients
    
    def _extract_names_from_text(self, text: str) -> List[str]:
        """Extrai possíveis nomes de clientes de um texto usando padrões"""
        if not text or len(text) < 3:
            return []
        
        names = set()
        
        # Tenta cada padrão
        for pattern in self.client_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                cleaned_name = self._clean_client_name(match)
                if cleaned_name:
                    names.add(cleaned_name)
        
        # Se não encontrou nada com padrões específicos, tenta extrair o texto todo
        if not names:
            cleaned_name = self._clean_client_name(text)
            if cleaned_name:
                names.add(cleaned_name)
        
        return list(names)
    
    def _clean_client_name(self, name: str) -> Optional[str]:
        """Limpa e valida um nome de cliente"""
        if not name:
            return None
        
        # Cache hit
        if name in self._name_cache:
            return self._name_cache[name]
        
        # Remove espaços extras e caracteres especiais desnecessários
        cleaned = re.sub(r'[^\w\s-]', '', name).strip()
        cleaned = re.sub(r'\s+', ' ', cleaned)
        
        # Remove prefixos/sufixos técnicos comuns
        cleaned = re.sub(r'^(PI|MA|CE|SP|RJ|MG|BA)-', '', cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r'-(PE\d+|CE\d+|WAN|LAN|INTERNET|VOICE|DATA)$', '', cleaned, flags=re.IGNORECASE)
        
        cleaned = cleaned.strip()
        
        # Validações
        if len(cleaned) < 3:
            self._name_cache[name] = None
            return None
        
        # Verifica se não é uma palavra técnica
        if cleaned.lower() in self.exclude_words:
            self._name_cache[name] = None
            return None
        
        # Verifica se tem pelo menos uma letra
        if not re.search(r'[a-zA-Z]', cleaned):
            self._name_cache[name] = None
            return None
        
        # Se passou em todas as validações
        self._name_cache[name] = cleaned
        return cleaned
    
    def _merge_clients(self, target: Dict, source: Dict):
        """Merge dois dicionários de clientes"""
        for client_name, occurrences in source.items():
            if client_name not in target:
                target[client_name] = []
            target[client_name].extend(occurrences)


class CustomerIndexUpdater:
    """Atualiza o índice CustomerIndex com dados extraídos dos JSONs"""
    
    def __init__(self):
        self.extractor = CustomerNameExtractor()
        
    def update_from_json_file(self, json_file_path: str, equipment_name: str) -> int:
        """
        Atualiza o índice a partir de um arquivo JSON
        
        Returns:
            Número de clientes processados
        """
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            
            return self.update_from_json_data(json_data, equipment_name, json_file_path)
            
        except Exception as e:
            logger.error(f"Erro ao processar arquivo {json_file_path}: {e}")
            return 0
    
    def update_from_json_data(self, json_data: Dict, equipment_name: str, source_file: str = "") -> int:
        """
        Atualiza o índice a partir de dados JSON
        
        Returns:
            Número de clientes processados
        """
        try:
            # Extrai clientes do JSON
            clients = self.extractor.extract_from_json(json_data, equipment_name, source_file)
            
            # Atualiza banco de dados
            clients_processed = 0
            
            for client_name, occurrences in clients.items():
                try:
                    # Normaliza nomes
                    normalized_name = CustomerIndex.normalize_name(client_name)
                    clean_name = CustomerIndex.clean_name(client_name)
                    
                    # Busca ou cria registro
                    customer_index, created = CustomerIndex.objects.get_or_create(
                        customer_name_normalized=normalized_name,
                        defaults={
                            'customer_name': client_name,
                            'customer_name_clean': clean_name,
                        }
                    )
                    
                    # Se já existia, atualiza nome original para o mais recente
                    if not created:
                        customer_index.customer_name = client_name
                        customer_index.customer_name_clean = clean_name
                    
                    # Adiciona cada ocorrência
                    for occurrence in occurrences:
                        customer_index.add_occurrence(
                            equipment_name=occurrence['equipment'],
                            vpn_id=occurrence['vpn_id'],
                            interface_name=occurrence['interface'],
                            description=occurrence['description'],
                            context_type=occurrence['context_type'],
                            source_file=occurrence['source_file']
                        )
                    
                    customer_index.save()
                    clients_processed += 1
                    
                except Exception as e:
                    logger.error(f"Erro ao salvar cliente {client_name}: {e}")
            
            logger.info(f"Processados {clients_processed} clientes de {equipment_name}")
            return clients_processed
            
        except Exception as e:
            logger.error(f"Erro ao atualizar índice para {equipment_name}: {e}")
            return 0
    
    def rebuild_full_index(self, json_directory: str) -> Dict[str, int]:
        """
        Reconstrói completamente o índice a partir de um diretório de JSONs
        
        Returns:
            Estatísticas do processamento
        """
        import os
        
        # Limpa índice atual
        CustomerIndex.objects.all().delete()
        
        stats = {
            'files_processed': 0,
            'files_failed': 0,
            'clients_found': 0,
            'total_occurrences': 0
        }
        
        # Processa todos os JSONs do diretório
        for filename in os.listdir(json_directory):
            if filename.endswith('.json'):
                file_path = os.path.join(json_directory, filename)
                equipment_name = filename.replace('.json', '')
                
                try:
                    clients_count = self.update_from_json_file(file_path, equipment_name)
                    stats['files_processed'] += 1
                    stats['clients_found'] += clients_count
                except Exception as e:
                    logger.error(f"Falha ao processar {filename}: {e}")
                    stats['files_failed'] += 1
        
        # Calcula total de ocorrências
        from django.db.models import Sum
        stats['total_occurrences'] = CustomerIndex.objects.aggregate(
            total=Sum('total_occurrences')
        )['total'] or 0
        
        logger.info(f"Índice reconstruído: {stats}")
        return stats


# Função utilitária para busca rápida
def search_customers_by_name(query: str, limit: int = 50) -> List[CustomerIndex]:
    """
    Busca rápida por clientes usando o índice otimizado
    
    Args:
        query: Termo de busca
        limit: Número máximo de resultados
    
    Returns:
        Lista de CustomerIndex ordenada por relevância
    """
    if not query or len(query) < 2:
        return []
    
    # Normaliza query
    query_normalized = CustomerIndex.normalize_name(query)
    query_clean = CustomerIndex.clean_name(query)
    
    from django.db.models import Q
    
    # Busca em múltiplos campos com pesos diferentes
    results = CustomerIndex.objects.filter(
        Q(customer_name_normalized__icontains=query_normalized) |
        Q(customer_name_clean__icontains=query_clean) |
        Q(customer_name__icontains=query)
    ).order_by('-total_occurrences', 'customer_name_normalized')[:limit]
    
    return list(results)


def search_customers_by_vpn_id(vpn_id: int) -> List[CustomerIndex]:
    """
    Busca clientes por VPN ID
    
    Args:
        vpn_id: ID da VPN
    
    Returns:
        Lista de CustomerIndex que contém essa VPN
    """
    return list(CustomerIndex.objects.filter(
        vpn_ids__contains=vpn_id
    ).order_by('-total_occurrences'))