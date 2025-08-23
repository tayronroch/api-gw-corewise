from django.db.models import Q
# PostgreSQL search disabled for development
# from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
# from django.contrib.postgres.aggregates import StringAgg
import re
from .models import MplsConfiguration, Equipment, CustomerService, Vpn


class AdvancedSearchEngine:
    """Motor de busca avançado para dados MPLS - SQLite version"""
    
    def __init__(self):
        self.search_config = 'portuguese_pt'
    
    def search_full_text(self, query, limit=50):
        """
        Busca textual completa em todas as configurações (SQLite version)
        Permite buscar por qualquer coisa: serial de SFP, IP, nome, etc.
        """
        if not query or len(query) < 2:
            return MplsConfiguration.objects.none()
        
        # Busca simples usando icontains para SQLite
        results = MplsConfiguration.objects.filter(
            Q(equipment__name__icontains=query) |
            Q(equipment__location__icontains=query) |
            Q(raw_config__icontains=query)
        ).select_related('equipment').order_by('-backup_date')
        
        return results[:limit]

    def search_vpn_id(self, vpn_id):
        """Busca configurações relacionadas a uma VPN ID específica"""
        try:
            vpn_id_int = int(vpn_id)
        except (TypeError, ValueError):
            return MplsConfiguration.objects.none()
        return (
            MplsConfiguration.objects
            .filter(vpws_groups__vpns__vpn_id=vpn_id_int)
            .select_related('equipment')
            .order_by('-backup_date')
            .distinct()
        )
    
    def search_equipment_configs(self, query, equipment_filter=None, location_filter=None):
        """Busca específica por configurações de equipamentos (SQLite version)"""
        queryset = MplsConfiguration.objects.select_related('equipment')
        
        if equipment_filter:
            queryset = queryset.filter(equipment__name__icontains=equipment_filter)
        
        if location_filter:
            queryset = queryset.filter(equipment__location__icontains=location_filter)
        
        if query:
            # Busca textual no conteúdo das configurações usando icontains
            queryset = queryset.filter(
                Q(equipment__name__icontains=query) |
                Q(equipment__location__icontains=query) |
                Q(raw_config__icontains=query)
            ).order_by('-backup_date')
        
        return queryset
    
    def search_by_pattern(self, pattern, pattern_type='regex'):
        """
        Busca por padrões específicos usando regex
        Útil para buscar seriais, MACs, IPs específicos, etc.
        """
        if pattern_type == 'regex':
            return MplsConfiguration.objects.filter(
                raw_config__regex=pattern
            ).select_related('equipment')
        else:
            return MplsConfiguration.objects.filter(
                raw_config__icontains=pattern
            ).select_related('equipment')
    
    def search_serial_numbers(self, serial):
        """Busca específica por números de série"""
        # Padrões comuns de serial numbers
        patterns = [
            rf'\b{re.escape(serial)}\b',  # Serial exato
            rf'serial[^:]*:?\s*{re.escape(serial)}',  # serial: XXXXX
            rf'Serial Number[^:]*:?\s*{re.escape(serial)}',  # Serial Number: XXXXX
        ]
        
        results = []
        for pattern in patterns:
            found = self.search_by_pattern(pattern, 'regex')
            results.extend(found)
        
        # Remove duplicatas mantendo ordem
        seen = set()
        unique_results = []
        for item in results:
            if item.id not in seen:
                seen.add(item.id)
                unique_results.append(item)
        
        return unique_results
    
    def search_ip_addresses(self, ip):
        """Busca por endereços IP específicos"""
        # Escapa pontos para regex
        escaped_ip = re.escape(ip)
        pattern = rf'\b{escaped_ip}\b'
        
        return self.search_by_pattern(pattern, 'regex')
    
    def search_mac_addresses(self, mac):
        """Busca por endereços MAC"""
        # Normaliza MAC address (remove separadores)
        clean_mac = re.sub(r'[:-]', '', mac.upper())
        
        # Padrões comuns de MAC
        patterns = [
            rf'{clean_mac[:2]}[:-]{clean_mac[2:4]}[:-]{clean_mac[4:6]}[:-]{clean_mac[6:8]}[:-]{clean_mac[8:10]}[:-]{clean_mac[10:12]}',
            rf'{clean_mac[:4]}\.{clean_mac[4:8]}\.{clean_mac[8:12]}',
            rf'{clean_mac}',
        ]
        
        results = []
        for pattern in patterns:
            found = self.search_by_pattern(pattern, 'regex')
            results.extend(found)
        
        return list(set(results))
    
    def search_vlans(self, vlan_id):
        """Busca por VLANs específicas"""
        patterns = [
            rf'\bvlan\s+{vlan_id}\b',
            rf'\bdot1q\s+{vlan_id}\b',
            rf'\bencapsulation\s+dot1q\s+{vlan_id}',
        ]
        
        results = []
        for pattern in patterns:
            found = self.search_by_pattern(pattern, 'regex')
            results.extend(found)
        
        return list(set(results))
    
    def search_interfaces(self, interface_name):
        """Busca por interfaces específicas"""
        escaped_interface = re.escape(interface_name)
        patterns = [
            rf'\binterface\s+{escaped_interface}\b',
            rf'\b{escaped_interface}\b',
        ]
        
        results = []
        for pattern in patterns:
            found = self.search_by_pattern(pattern, 'regex')
            results.extend(found)
        
        return list(set(results))
    
    def extract_search_highlights(self, config_text, query, max_snippets=3):
        """
        Extrai trechos relevantes do texto da configuração
        para destacar onde a busca foi encontrada
        """
        if not query:
            return []
        
        snippets = []
        lines = config_text.split('\n')
        query_lower = query.lower()
        
        for i, line in enumerate(lines):
            if query_lower in line.lower():
                # Pega contexto (linha anterior e posterior)
                start = max(0, i - 1)
                end = min(len(lines), i + 2)
                
                context_lines = lines[start:end]
                snippet = '\n'.join(context_lines)
                
                # Destaca o termo encontrado
                highlighted = re.sub(
                    f'({re.escape(query)})', 
                    r'<mark>\1</mark>', 
                    snippet, 
                    flags=re.IGNORECASE
                )
                
                snippets.append({
                    'text': highlighted,
                    'line_number': i + 1
                })
                
                if len(snippets) >= max_snippets:
                    break
        
        return snippets
    
    def update_all_search_vectors(self):
        """Search vectors disabled for SQLite"""
        return 0


def smart_search(query, search_type='auto', **filters):
    """
    Função helper para busca inteligente
    Detecta automaticamente o tipo de busca baseado no padrão da query
    """
    engine = AdvancedSearchEngine()
    
    if search_type == 'auto':
        # Detecta o tipo baseado no padrão
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query):
            search_type = 'ip'
        elif re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', query):
            search_type = 'mac'
        elif re.match(r'^\d+$', query):
            # Prioriza VPN ID se existir; caso contrário, tenta VLAN para números curtos
            vpn_results = engine.search_vpn_id(query)
            if vpn_results.exists():
                return vpn_results
            search_type = 'vlan' if len(query) <= 4 else 'full_text'
        elif any(keyword in query.lower() for keyword in ['interface', 'gi', 'fa', 'eth']):
            search_type = 'interface'
        elif len(query) > 8 and re.match(r'^[A-Z0-9]+$', query):
            search_type = 'serial'
        else:
            search_type = 'full_text'
    
    # Executa busca baseada no tipo
    if search_type == 'full_text':
        return engine.search_full_text(query)
    elif search_type == 'ip':
        return engine.search_ip_addresses(query)
    elif search_type == 'mac':
        return engine.search_mac_addresses(query)
    elif search_type == 'vlan':
        return engine.search_vlans(query)
    elif search_type == 'interface':
        return engine.search_interfaces(query)
    elif search_type == 'serial':
        return engine.search_serial_numbers(query)
    elif search_type == 'vpn':
        return engine.search_vpn_id(query)
    else:
        return engine.search_equipment_configs(query, **filters)


def bulk_update_search_vectors():
    """Search vectors disabled for SQLite"""
    return 0