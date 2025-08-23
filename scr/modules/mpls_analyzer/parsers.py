import re
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from django.utils import timezone

from .models import (
    Equipment, MplsConfiguration, VpwsGroup, Vpn, 
    LdpNeighbor, CustomerService, Interface, LagMember
)


class MplsConfigParser:
    def __init__(self):
        self.vpws_pattern = re.compile(r'vpws-group\s+(\S+)')
        self.vpn_pattern = re.compile(r'vpn\s+(\d+)')
        self.neighbor_pattern = re.compile(r'neighbor\s+([\d.]+)')
        self.pw_type_pattern = re.compile(r'pw-type\s+(\S+)\s+(\d+)')
        self.pw_id_pattern = re.compile(r'pw-id\s+(\d+)')
        self.encap_pattern = re.compile(r'dot1q\s+([\d\-,]+)')
        self.interface_pattern = re.compile(r'access-interface\s+(\S+)')
        self.ldp_neighbor_pattern = re.compile(r'neighbor\s+targeted\s+([\d.]+)')

    def extract_customer_name_from_equipment(self, equipment_name: str) -> Optional[str]:
        """Extrai nome do cliente do nome do equipamento"""
        patterns = [
            r'[A-Z]{2}-[A-Z]+-([A-Z]+)-[A-Z]{2}\d+',  # PI-TERESINA-VELOCINET-CE01
            r'DIRECT-([A-Z]+)-[A-Z]+-[A-Z]{2}\d+',    # DIRECT-DIGITALNET-MARCELO-CE01
        ]
        
        for pattern in patterns:
            match = re.search(pattern, equipment_name)
            if match:
                return match.group(1).replace('-', '').upper()
        
        return None

    def extract_customers_from_descriptions(self, content: str) -> List[str]:
        """Extrai nomes de clientes das descrições de interfaces"""
        customers = []
        
        # Padrões para extrair clientes de descrições (ordem específica -> geral)
        # Usa [A-Z0-9&] para permitir letras, números e & no nome do cliente
        patterns = [
            # LINK-CLIENTE-LOCAL-INTERFACE (formato VPN)
            r'description\s+LINK-([A-Z0-9&]+)-[A-Z0-9]+-[A-Z0-9/]+',
            # CUSTOMER-ISP-CLIENTE-LOCAL-L2L-VL4050 (mais específico)
            r'description\s+CUSTOMER-ISP-([A-Z0-9&]+(?:-[A-Z0-9&]+)*)',
            # CUSTOMER-CLIENTE-LINK-R1-LAG14-VL529 (com LINK no meio)
            r'description\s+CUSTOMER-([A-Z0-9&]+)-LINK-R\d+',
            # CUSTOMER-LINK-CLIENTE-OUTRO-VL808
            r'description\s+CUSTOMER-LINK-([A-Z0-9&]+(?:-[A-Z0-9&]+)*)',
            # CUSTOMER-CLIENTE-P1-LAG10-DIRECT (formato com DIRECT)
            r'description\s+CUSTOMER-([A-Z0-9&]+)-P\d+-LAG\d+-DIRECT',
            # CUSTOMER-CLIENTE-P1-LAG11-CABO1 (formato com CABO)
            r'description\s+CUSTOMER-([A-Z0-9&]+)-P\d+-LAG\d+-CABO\d+',
            # CUSTOMER-CLIENTE-L2L-P1-LAG12 (formato com LAG)
            r'description\s+CUSTOMER-([A-Z0-9&]+)-L2L-P\d+-LAG\d+',
            # CUSTOMER-CLIENTE-L2L-P1 (formato simples com porta)
            r'description\s+CUSTOMER-([A-Z0-9&]+)-L2L-P\d+',
            # CUSTOMER-CLIENTE-L2L-VL2406 (com caracteres especiais)
            r'description\s+CUSTOMER-([A-Z0-9&]+)-L2L-VL\d+',
            # CUSTOMER-CLIENTE-LOCAL-L2L-VL1805 (sem ISP/LINK)
            r'description\s+CUSTOMER-([A-Z0-9&]+(?:-[A-Z0-9&]+)*)-[A-Z]+-L2L',
            # CUSTOMER-CLIENTE-NNI-VL519 (formato NNI)
            r'description\s+CUSTOMER-([A-Z0-9&]+(?:-[A-Z0-9&]+)*)-NNI',
            # CUSTOMER-CLIENTE-R1-P1-LAG10 (formato com equipamento)
            r'description\s+CUSTOMER-([A-Z0-9&]+(?:-[A-Z0-9&]+)*)-R\d+',
            # CUSTOMER-CLIENTE-L2L-VL2702 (formato simples)
            r'description\s+CUSTOMER-([A-Z0-9&]+(?:-[A-Z0-9&]+)*)-L2L',
            # CUSTOMER-CLIENTE-EXTAND-EVENTOS-VL766 (formato com serviço)
            r'description\s+CUSTOMER-([A-Z0-9&]+(?:-[A-Z0-9&]+)*)-[A-Z]+-[A-Z]+',
            # CUSTOMER-CLIENTE (formato mais geral - por último)
            r'description\s+CUSTOMER-([A-Z0-9&]+(?:-[A-Z0-9&]+)*)',
            # ISP-L2L-CLIENTE
            r'description\s+ISP-L2L-([A-Z0-9&]+)',
            # CLIENTE-L2L (sem CUSTOMER)
            r'description\s+([A-Z0-9&]+)-L2L',
            # VIA-CLIENTE
            r'VIA-([A-Z0-9&]+)',
        ]
        
        # Lista de nomes genéricos para filtrar
        generic_names = {
            'ISP', 'CUSTOMER', 'VL', 'LAG', 'GE', 'ETHERNET', 'INTERFACE', 
            'L2L', 'VIA', 'PE01', 'PE02', 'CE01', 'CE02', 'LOCAL', 
            'LINK', 'NET', 'WAN', 'LAN', 'NNI', 'FASE', 'ATIVACAO',
            'ID', 'TRELLO', 'VL', 'P1', 'P2', 'R1', 'R2', 'LAG',
            'EXTAND', 'EVENTOS', 'MARCELO', 'RENATO', 'EVILSON',
            'DIRECT', 'CABO', 'CABO1', 'CABO2', 'UPS'
        }
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                customer_name = match.group(1).upper()
                
                # Remove hífens extras e divide nomes compostos
                customer_parts = customer_name.split('-')
                main_customer = customer_parts[0]
                
                # Permite nomes com 3+ chars, ou com caracteres especiais (&)
                min_length = 2 if '&' in main_customer else 3
                
                # Filtra nomes muito genéricos, muito curtos ou números
                if (len(main_customer) > min_length and 
                    main_customer not in generic_names and
                    not main_customer.isdigit() and
                    main_customer not in customers):
                    customers.append(main_customer)
        
        return customers

    def extract_customers_from_vpn_descriptions(self, vpws_groups: List[Dict]) -> List[str]:
        """Extrai nomes de clientes das descrições das VPNs"""
        customers = []
        
        for group in vpws_groups:
            for vpn in group.get('vpns', []):
                description = vpn.get('description', '')
                if description:
                    # Aplica os mesmos padrões de extração nas descrições VPN
                    vpn_customers = self.extract_customers_from_descriptions(f"description {description}")
                    customers.extend(vpn_customers)
        
        # Remove duplicatas mantendo ordem
        unique_customers = []
        for customer in customers:
            if customer not in unique_customers:
                unique_customers.append(customer)
        
        return unique_customers

    def parse_config_file(self, file_path: str) -> Dict:
        """Processa arquivo de configuração e extrai dados MPLS"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Auto-detecção: JSON do novo formato ou CLI
            stripped = content.strip()
            if file_path.endswith('.json'):
                # Novo formato JSON estruturado com metadata
                try:
                    json_data = json.loads(stripped)
                    if 'data' in json_data:
                        # Novo formato com metadata
                        return self.parse_device_json_text(json.dumps(json_data['data']))
                    else:
                        # Formato JSON direto
                        return self.parse_device_json_text(stripped)
                except json.JSONDecodeError:
                    pass
            
            if stripped.startswith('{') and (
                'dmos-sys-config:system' in stripped or 'l2-vpn:l2vpn-config' in stripped
            ):
                # Delegar para o parser de JSON DMOS
                return self.parse_device_json_text(stripped)

            equipment_name = os.path.basename(file_path).replace('.txt', '').replace('.json', '')
            
            # Extrai interfaces e suas descrições
            customer_interfaces = self._parse_interfaces_from_text(content)
            
            # Extrai clientes das descrições
            description_customers = self.extract_customers_from_descriptions(content)
            
            # Parse VPWS groups primeiro
            vpws_groups = self._parse_vpws_groups(content)
            
            # Extrai clientes das descrições VPN
            vpn_description_customers = self.extract_customers_from_vpn_descriptions(vpws_groups)
            
            # Combina todos os clientes (descrições de interface + descrições VPN)
            all_description_customers = list(description_customers)
            for customer in vpn_description_customers:
                if customer not in all_description_customers:
                    all_description_customers.append(customer)
            
            parsed_data = {
                'equipment_name': equipment_name,
                'customer_name': self.extract_customer_name_from_equipment(equipment_name),
                'description_customers': all_description_customers,
                'vpn_description_customers': vpn_description_customers,
                'vpws_groups': vpws_groups,
                'ldp_neighbors': [],
                'customer_interfaces': customer_interfaces,
                'raw_config': content
            }
            
            # Parse LDP neighbors
            ldp_neighbors = self._parse_ldp_neighbors(content)
            parsed_data['ldp_neighbors'] = ldp_neighbors
            
            return parsed_data
            
        except Exception as e:
            raise Exception(f"Erro ao processar arquivo {file_path}: {str(e)}")

    # -------------------- NOVO: Parsing de JSON DMOS --------------------
    def parse_device_json_text(self, json_text: str) -> Dict:
        """Processa saída JSON do equipamento (DMOS) e retorna estrutura compatível com save_to_database"""
        data = json.loads(json_text)
        # Em algumas saídas, o JSON vem dentro de {"data": {...}}
        root = data.get('data', data)

        # Hostname
        hostname = (
            root.get('dmos-base:config', {})
                .get('dmos-sys-config:system', {})
                .get('hostname')
        ) or root.get('hostname') or 'UNKNOWN'

        # Loopback IP (usa como IP do equipamento) - CORRIGIDO para buscar loopback 0
        loopbacks = (
            root.get('dmos-base:config', {})
                .get('interface', {})
                .get('dmos-ip-application:loopback', [])
        )
        equipment_ip = None
        try:
            # Busca especificamente o loopback 0
            for loopback in loopbacks:
                if loopback.get('id') == '0':
                    addr_list = loopback.get('ipv4', {}).get('address', [])
                    if addr_list:
                        ip_with_mask = addr_list[0].get('ip', '')
                        if ip_with_mask:
                            equipment_ip = ip_with_mask.split('/')[0]
                            break
        except Exception:
            pass

        # Mapear descrições de LAGs e seus membros
        lags = (
            root.get('lacp:link-aggregation', {})
                .get('interface', {})
                .get('lag', [])
        )
        lag_descriptions = {}
        lag_members = {}
        customer_lags = []  # Lista de LAGs de clientes
        
        for lag in lags:
            lag_id = lag.get('lag-id')
            desc = (lag.get('interface-lag-config') or {}).get('description', '')
            if lag_id is not None:
                lag_name = f'lag-{lag_id}'
                lag_descriptions[lag_name] = desc
                members = [m.get('interface-name') for m in (lag.get('interface-config') or []) if m.get('interface-name')]
                lag_members[lag_name] = members
                
                # Identificar LAGs de clientes (baseado na descrição ou members com CUSTOMER)
                is_customer_lag = False
                if any(keyword in desc.upper() for keyword in ['ISP-', 'AGG-L2L-', 'CUSTOMER-']) and not any(pe in desc.upper() for pe in ['PE01', 'PE02', 'SANTANADOMARANHAO', 'PLACAS']):
                    is_customer_lag = True
                
                if is_customer_lag:
                    customer_lags.append({
                        'interface': lag_name,
                        'description': desc,
                        'members': members,
                        'type': 'lag'
                    })

        # Mapear descrições de interfaces físicas - identificar interfaces de clientes
        gigabit_list = (
            root.get('dmos-base:config', {})
                .get('interface', {})
                .get('dmos-interface-ethernet:gigabit-ethernet', [])
        )
        ten_g_list = (
            root.get('dmos-base:config', {})
                .get('interface', {})
                .get('dmos-interface-ethernet:ten-gigabit-ethernet', [])
        )
        twenty_five_g_list = (
            root.get('dmos-base:config', {})
                .get('interface', {})
                .get('dmos-interface-ethernet:twenty-five-g-ethernet', [])
        )
        forty_g_list = (
            root.get('dmos-base:config', {})
                .get('interface', {})
                .get('dmos-interface-ethernet:forty-gigabit-ethernet', [])
        )
        hundred_g_list = (
            root.get('dmos-base:config', {})
                .get('interface', {})
                .get('dmos-interface-ethernet:hundred-gigabit-ethernet', [])
        )
        if_desc = {}
        customer_interfaces = []  # Lista de interfaces de clientes
        
        # Processar interfaces de 1G
        for it in gigabit_list:
            name = f"gigabit-ethernet-{it.get('chassis-id')}/{it.get('slot-id')}/{it.get('port-id')}"
            description = it.get('description', '')
            if_desc[name] = description
            
            # Identificar se é interface de cliente
            if description.startswith('CUSTOMER-'):
                customer_interfaces.append({
                    'interface': name,
                    'description': description,
                    'speed': '1G',
                    'type': 'physical'
                })
        
        # Processar interfaces de 10G
        for it in ten_g_list:
            name = f"ten-gigabit-ethernet-{it.get('chassis-id')}/{it.get('slot-id')}/{it.get('port-id')}"
            description = it.get('description', '')
            if_desc[name] = description
            
            # Identificar se é interface de cliente
            if description.startswith('CUSTOMER-'):
                customer_interfaces.append({
                    'interface': name,
                    'description': description,
                    'speed': '10G',
                    'type': 'physical'
                })
        
        # Processar interfaces de 25G
        for it in twenty_five_g_list:
            name = f"twenty-five-g-ethernet-{it.get('chassis-id')}/{it.get('slot-id')}/{it.get('port-id')}"
            description = it.get('description', '')
            if_desc[name] = description
            
            # Identificar se é interface de cliente
            if description.startswith('CUSTOMER-'):
                customer_interfaces.append({
                    'interface': name,
                    'description': description,
                    'speed': '25G',
                    'type': 'physical'
                })
        
        # Processar interfaces de 40G
        for it in forty_g_list:
            name = f"forty-gigabit-ethernet-{it.get('chassis-id')}/{it.get('slot-id')}/{it.get('port-id')}"
            description = it.get('description', '')
            if_desc[name] = description
            
            # Identificar se é interface de cliente
            if description.startswith('CUSTOMER-'):
                customer_interfaces.append({
                    'interface': name,
                    'description': description,
                    'speed': '40G',
                    'type': 'physical'
                })
        
        # Processar interfaces de 100G
        for it in hundred_g_list:
            name = f"hundred-gigabit-ethernet-{it.get('chassis-id')}/{it.get('slot-id')}/{it.get('port-id')}"
            description = it.get('description', '')
            if_desc[name] = description
            
            # Interface de cliente DEVE começar com CUSTOMER- (rigoroso como especificado)
            if description.startswith('CUSTOMER-'):
                customer_interfaces.append({
                    'interface': name,
                    'description': description,
                    'speed': '100G',
                    'type': 'physical'
                })

        # VPWS/VPNS
        vpws_groups_json = (
            root.get('router-mpls:mpls', {})
                .get('l2-vpn:l2vpn-config', {})
                .get('l2vpn', {})
                .get('vpws-group', [])
        )
        vpws_groups = []
        for group in vpws_groups_json:
            group_name = group.get('group-name') or ''
            vpns_out = []
            for vpn in group.get('vpn', []):
                vpn_id_str = vpn.get('vpn-name')
                try:
                    vpn_id = int(vpn_id_str) if vpn_id_str is not None else None
                except Exception:
                    vpn_id = None
                neighbor_list = vpn.get('neighbor', [])
                neighbor_ip = neighbor_list[0].get('neighbor-ip') if neighbor_list else None
                pw_type_obj = neighbor_list[0].get('pw-type') if neighbor_list else {}
                pw_type = (pw_type_obj or {}).get('type', '')
                pw_id = (pw_type_obj or {}).get('service-delimiting') or vpn.get('pw-id')
                access_list = vpn.get('access-interface', [])
                access_if = access_list[0].get('interface-name') if access_list else ''
                # Encapsulation - melhor detecção do tipo de encapsulamento
                encap = ''
                encap_type = 'untagged'
                access_interface_data = access_list[0] if access_list else {}
                
                # Verifica se há encapsulamento específico
                encap_obj = access_interface_data.get('dmos-mpls-l2vpn-vpws:encapsulation')
                if encap_obj and 'dot1q' in encap_obj:
                    dot1q_value = str(encap_obj.get('dot1q'))
                    encap = dot1q_value
                    
                    # Se tem múltiplas VLANs (espaçadas ou separadas por hífen), é QinQ
                    if ' ' in dot1q_value or '-' in dot1q_value:
                        encap_type = 'qinq'
                        encap = f"qinq:{dot1q_value}"
                    else:
                        encap_type = 'vlan_tagged'
                        encap = f"vlan:{dot1q_value}"
                
                # Verifica dot1q diretamente no access-interface (formato alternativo)
                elif 'dot1q' in access_interface_data:
                    dot1q_value = str(access_interface_data.get('dot1q'))
                    encap = f"vlan:{dot1q_value}"
                    encap_type = 'vlan_tagged'
                
                # Flag qinq explícita
                if 'qinq' in vpn and vpn.get('qinq') is not None:
                    encap_type = 'qinq'
                    if not encap.startswith('qinq:'):
                        encap = f"qinq:{encap}" if encap else 'qinq'

                # Descrição da VPN
                description = vpn.get('description', '')
                # Fallback: descrição da interface física ou LAG
                if not description and access_if:
                    if access_if.startswith('lag-'):
                        description = lag_descriptions.get(access_if, '')
                    else:
                        description = if_desc.get(access_if, '')

                vpn_out = {
                    'vpn_id': vpn_id,
                    'neighbor_ip': neighbor_ip,
                    'pw_type': pw_type or '',
                    'pw_id': int(pw_id) if isinstance(pw_id, int) or (isinstance(pw_id, str) and pw_id.isdigit()) else 0,
                    'encapsulation': encap,
                    'encapsulation_type': encap_type,
                    'access_interface': access_if,
                    'description': description or '',
                    'customer_names': self.extract_customers_from_descriptions(f"description {description}") if description else []
                }
                if vpn_out['vpn_id'] is not None and vpn_out['neighbor_ip']:
                    vpns_out.append(vpn_out)

            vpws_groups.append({
                'group_name': group_name,
                'vpns': vpns_out
            })

        # Monta raw_config minimamente útil (para extrair clientes das descrições)
        desc_lines = []
        
        # Adiciona interfaces físicas
        for name, desc in if_desc.items():
            if desc:
                desc_lines.append(f"interface {name}\n description {desc}")
        
        # Adiciona LAGs
        for lag_name, desc in lag_descriptions.items():
            if desc:
                desc_lines.append(f"interface {lag_name}\n description {desc}")
        
        raw_config = "\n".join(desc_lines)

        # Clientes a partir das descrições
        description_customers = self.extract_customers_from_descriptions(raw_config)

        parsed_data = {
            'equipment_name': hostname,
            'equipment_ip': equipment_ip or None,
            'customer_name': self.extract_customer_name_from_equipment(hostname),
            'description_customers': description_customers,
            'vpn_description_customers': [],
            'vpws_groups': vpws_groups,
            'ldp_neighbors': [],
            'raw_config': raw_config or json_text,  # guarda JSON se não tiver descrições
            'customer_interfaces': customer_interfaces,
            'customer_lags': customer_lags,
            'lag_members': lag_members
        }

        # LDP targeted neighbors
        ldp_lsr = (
            root.get('router-mpls:mpls', {})
                .get('ldp-config', {})
                .get('ldp', {})
                .get('lsr-id', [])
        )
        neighbors = []
        for lsr in ldp_lsr:
            for n in lsr.get('neighbor', []) or []:
                ip = n.get('targeted')
                if ip and ip not in neighbors:
                    neighbors.append(ip)
        parsed_data['ldp_neighbors'] = neighbors

        return parsed_data

    def _parse_vpws_groups(self, content: str) -> List[Dict]:
        """Extrai grupos VPWS da configuração"""
        vpws_groups = []
        lines = content.split('\n')
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            vpws_match = self.vpws_pattern.search(line)
            
            if vpws_match:
                group_name = vpws_match.group(1)
                group_data = {
                    'group_name': group_name,
                    'vpns': []
                }
                
                # Processa VPNs dentro do grupo
                i += 1
                vpn_data = {}
                
                while i < len(lines) and not lines[i].strip().startswith('!'):
                    line = lines[i].strip()
                    
                    # VPN ID
                    vpn_match = self.vpn_pattern.search(line)
                    if vpn_match:
                        if vpn_data:  # Salva VPN anterior se existir
                            group_data['vpns'].append(vpn_data)
                        vpn_data = {'vpn_id': int(vpn_match.group(1))}
                    
                    # Descrição da VPN
                    if 'description' in line and 'vpn_id' in vpn_data:
                        desc_match = re.search(r'description\s+(.+)', line)
                    if desc_match:
                        desc_text = desc_match.group(1).strip()
                        vpn_data['description'] = desc_text
                        # Clientes por VPN a partir da descrição
                        vpn_data['customer_names'] = self.extract_customers_from_descriptions(f"description {desc_text}")
                    
                    # Neighbor IP
                    neighbor_match = self.neighbor_pattern.search(line)
                    if neighbor_match and 'neighbor_ip' not in vpn_data:
                        vpn_data['neighbor_ip'] = neighbor_match.group(1)
                    
                    # PW Type and ID
                    pw_type_match = self.pw_type_pattern.search(line)
                    if pw_type_match:
                        vpn_data['pw_type'] = pw_type_match.group(1)
                        vpn_data['pw_id'] = int(pw_type_match.group(2))
                    
                    # PW ID separado
                    pw_id_match = self.pw_id_pattern.search(line)
                    if pw_id_match and 'pw_id' not in vpn_data:
                        vpn_data['pw_id'] = int(pw_id_match.group(1))
                    
                    # Encapsulation
                    encap_match = self.encap_pattern.search(line)
                    if encap_match:
                        vpn_data['encapsulation'] = encap_match.group(1)
                    
                    # Access Interface
                    interface_match = self.interface_pattern.search(line)
                    if interface_match:
                        vpn_data['access_interface'] = interface_match.group(1)
                    
                    i += 1
                
                # Adiciona última VPN se existir
                if vpn_data and 'vpn_id' in vpn_data:
                    group_data['vpns'].append(vpn_data)
                
                vpws_groups.append(group_data)
            
            i += 1
        
        return vpws_groups

    def _parse_ldp_neighbors(self, content: str) -> List[str]:
        """Extrai vizinhos LDP da configuração"""
        neighbors = []
        
        for match in self.ldp_neighbor_pattern.finditer(content):
            neighbor_ip = match.group(1)
            if neighbor_ip not in neighbors:
                neighbors.append(neighbor_ip)
        
        return neighbors

    def save_to_database(self, parsed_data: Dict, backup_date: datetime = None) -> Equipment:
        """Salva dados processados no banco de dados com limpeza prévia"""
        if backup_date is None:
            backup_date = timezone.now()
        
        # Determina tipo do equipamento baseado no nome
        equipment_name = parsed_data['equipment_name']
        if '-CE' in equipment_name:
            equipment_type = 'CE'
        elif '-PE' in equipment_name:
            equipment_type = 'PE'
        else:
            equipment_type = 'P'
        
        # Extrai localização do nome
        location_match = re.match(r'([A-Z]{2})-([A-Z\-]+)', equipment_name)
        location = f"{location_match.group(1)}-{location_match.group(2)}" if location_match else ""
        
        # Busca IP do equipamento no banco de dados JSON original
        # Preferir IP vindo do parsing (loopback). Se não houver, buscar no banco JSON auxiliar
        equipment_ip = parsed_data.get('equipment_ip') or self._get_equipment_ip(equipment_name)
        
        # Cria ou atualiza equipamento
        equipment, created = Equipment.objects.get_or_create(
            name=equipment_name,
            defaults={
                'ip_address': equipment_ip or '0.0.0.0',
                'location': location,
                'equipment_type': equipment_type,
                'last_backup': backup_date
            }
        )
        
        if not created:
            equipment.last_backup = backup_date
            if equipment_ip:
                equipment.ip_address = equipment_ip
            equipment.save()
        
        # LIMPEZA MELHORADA: Remove TODAS as configurações antigas deste equipamento para evitar duplicidades
        # Isso garante que não haja VPNs duplicadas ou dados inconsistentes
        print(f"🧹 Limpando dados antigos do equipamento {equipment_name}...")
        
        # Remove serviços de clientes associados às VPNs antigas
        CustomerService.objects.filter(vpn__vpws_group__mpls_config__equipment=equipment).delete()
        
        # Remove VPNs antigas
        Vpn.objects.filter(vpws_group__mpls_config__equipment=equipment).delete()
        
        # Remove grupos VPWS antigos
        VpwsGroup.objects.filter(mpls_config__equipment=equipment).delete()
        
        # Remove interfaces antigas
        Interface.objects.filter(mpls_config__equipment=equipment).delete()
        
        # Remove membros de LAG antigos
        LagMember.objects.filter(lag_interface__mpls_config__equipment=equipment).delete()
        
        # Remove vizinhos LDP antigos
        LdpNeighbor.objects.filter(mpls_config__equipment=equipment).delete()
        
        # Remove as configurações antigas
        MplsConfiguration.objects.filter(equipment=equipment).delete()
        
        # Cria configuração MPLS
        mpls_config = MplsConfiguration.objects.create(
            equipment=equipment,
            backup_date=backup_date,
            raw_config=parsed_data['raw_config']
        )
        
        # Salva interfaces de clientes identificadas
        customer_interfaces = parsed_data.get('customer_interfaces', [])
        for if_data in customer_interfaces:
            Interface.objects.create(
                mpls_config=mpls_config,
                name=if_data['interface'],
                description=if_data['description'],
                interface_type=if_data['type'],
                speed=if_data.get('speed', ''),
                is_customer_interface=True
            )
        
        # Salva LAGs de clientes identificados
        customer_lags = parsed_data.get('customer_lags', [])
        lag_members = parsed_data.get('lag_members', {})
        for lag_data in customer_lags:
            lag_interface = Interface.objects.create(
                mpls_config=mpls_config,
                name=lag_data['interface'],
                description=lag_data['description'],
                interface_type='lag',
                is_customer_interface=True
            )
            
            # Salva membros do LAG
            members = lag_members.get(lag_data['interface'], [])
            for member_name in members:
                LagMember.objects.create(
                    lag_interface=lag_interface,
                    member_interface_name=member_name
                )
        
        # Indexa clientes por interface para associação correta (evita vincular todos os clientes a todas as VPNs)
        customers_by_interface = {}
        for if_data in parsed_data.get('customer_interfaces', []):
            desc = if_data.get('description', '') or ''
            names = self.extract_customers_from_descriptions(f"description {desc}") if desc else []
            customers_by_interface[if_data.get('interface')] = names

        # Indexa clientes por LAG
        customers_by_lag = {}
        for lag_data in parsed_data.get('customer_lags', []):
            desc = lag_data.get('description', '') or ''
            names = self.extract_customers_from_descriptions(f"description {desc}") if desc else []
            customers_by_lag[lag_data.get('interface')] = names

        # Processa grupos VPWS
        for vpws_data in parsed_data['vpws_groups']:
            vpws_group = VpwsGroup.objects.create(
                mpls_config=mpls_config,
                group_name=vpws_data['group_name']
            )
            
            # Processa VPNs
            for vpn_data in vpws_data['vpns']:
                if 'neighbor_ip' in vpn_data and 'vpn_id' in vpn_data:
                    # Resolve hostname do vizinho se já existir no banco
                    neighbor_hostname = ''
                    try:
                        neighbor_equipment = Equipment.objects.get(ip_address=vpn_data['neighbor_ip'])
                        neighbor_hostname = neighbor_equipment.name
                    except Equipment.DoesNotExist:
                        neighbor_hostname = ''

                    vpn = Vpn.objects.create(
                        vpws_group=vpws_group,
                        vpn_id=vpn_data['vpn_id'],
                        description=vpn_data.get('description', ''),
                        neighbor_ip=vpn_data['neighbor_ip'],
                        neighbor_hostname=neighbor_hostname,
                        pw_type=vpn_data.get('pw_type', ''),
                        pw_id=vpn_data.get('pw_id', 0),
                        encapsulation=vpn_data.get('encapsulation', ''),
                        encapsulation_type=vpn_data.get('encapsulation_type', 'untagged'),
                        access_interface=vpn_data.get('access_interface', '')
                    )
                    # Determina clientes associados especificamente a esta VPN
                    specific_customers = []

                    # 1) Clientes extraídos da descrição da própria VPN
                    specific_customers.extend(vpn_data.get('customer_names', []))

                    # 2) Clientes associados pela interface de acesso (física ou LAG)
                    access_if = vpn_data.get('access_interface', '')
                    if access_if:
                        if access_if.startswith('lag-'):
                            specific_customers.extend(customers_by_lag.get(access_if, []))
                        else:
                            specific_customers.extend(customers_by_interface.get(access_if, []))

                    # 3) Cliente derivado do nome do equipamento: somente para CE
                    if parsed_data.get('customer_name') and equipment.equipment_type == 'CE':
                        specific_customers.append(parsed_data['customer_name'])

                    # Remove duplicatas preservando ordem
                    seen_customers = set()
                    unique_customers = []
                    for name in specific_customers:
                        if name and name not in seen_customers:
                            seen_customers.add(name)
                            unique_customers.append(name)

                    # Persiste serviços vinculando APENAS aos clientes dessa VPN
                    for customer_name in unique_customers:
                        CustomerService.objects.get_or_create(
                            name=customer_name,
                            vpn=vpn,
                            defaults={
                                'service_type': 'vpn',
                                'bandwidth': ''
                            }
                        )
        
        # Processa vizinhos LDP
        for neighbor_ip in parsed_data['ldp_neighbors']:
            LdpNeighbor.objects.get_or_create(
                mpls_config=mpls_config,
                neighbor_ip=neighbor_ip,
                defaults={'targeted': True}
            )
        
        # Cria serviços para clientes das descrições mesmo sem VPN específica
        # (para equipamentos que não têm VPN configurada mas têm clientes nas descrições)
        if parsed_data.get('description_customers') and not parsed_data['vpws_groups']:
            # Cria uma VPN fictícia para poder associar os clientes
            dummy_vpws = VpwsGroup.objects.create(
                mpls_config=mpls_config,
                group_name='INTERFACE_DESCRIPTIONS'
            )
            
            dummy_vpn = Vpn.objects.create(
                vpws_group=dummy_vpws,
                vpn_id=0,  # ID fictício
                neighbor_ip='0.0.0.0',  # IP fictício
                pw_type='description_based',
                pw_id=0,
                encapsulation='',
                access_interface='interface_descriptions'
            )
            
            for customer_name in parsed_data['description_customers']:
                CustomerService.objects.get_or_create(
                    name=customer_name,
                    vpn=dummy_vpn,
                    defaults={
                        'service_type': 'data',
                        'bandwidth': ''
                    }
                )
        
        return equipment

    def _parse_interfaces_from_text(self, content: str) -> List[Dict]:
        """Extrai interfaces e suas descrições de configurações de texto"""
        interfaces = []
        
        # Padrões para diferentes tipos de interface
        interface_patterns = [
            r'interface\s+(ten-gigabit-ethernet-\d+/\d+/\d+)\s*\n\s*description\s+(.+)',
            r'interface\s+(twenty-five-g-ethernet-\d+/\d+/\d+)\s*\n\s*description\s+(.+)',
            r'interface\s+(hundred-gigabit-ethernet-\d+/\d+/\d+)\s*\n\s*description\s+(.+)',
            r'interface\s+(gigabit-ethernet-\d+/\d+/\d+)\s*\n\s*description\s+(.+)',
            r'interface\s+(forty-gigabit-ethernet-\d+/\d+/\d+)\s*\n\s*description\s+(.+)',
        ]
        
        for pattern in interface_patterns:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                interface_name = match.group(1)
                description = match.group(2).strip()
                
                # Determina velocidade baseada no tipo de interface
                speed = '1G'
                if 'ten-gigabit' in interface_name.lower():
                    speed = '10G'
                elif 'twenty-five-g' in interface_name.lower():
                    speed = '25G'
                elif 'forty-gigabit' in interface_name.lower():
                    speed = '40G'
                elif 'hundred-gigabit' in interface_name.lower():
                    speed = '100G'
                
                # Só inclui se for interface de cliente
                if description.startswith('CUSTOMER-'):
                    interfaces.append({
                        'interface': interface_name,
                        'description': description,
                        'speed': speed,
                        'type': 'physical'
                    })
        
        return interfaces

    def _get_equipment_ip(self, equipment_name: str) -> Optional[str]:
        """Busca IP do equipamento no banco de dados JSON"""
        try:
            json_path = '/home/tayron/Documentos/GitHub/SeachBackbone/banco-de-dados.json'
            with open(json_path, 'r', encoding='utf-8') as f:
                devices = json.load(f)
            
            for device in devices:
                if device['name'] == equipment_name:
                    return device['ip']
            
        except Exception:
            pass
        
        return None


class BackupProcessor:
    def __init__(self):
        self.parser = MplsConfigParser()
    
    def process_backup_directory(self, backup_dir: str) -> Tuple[int, int, List[str]]:
        """Processa todos os arquivos de backup de um diretório"""
        processed_files = 0
        total_files = 0
        errors = []
        
        if not os.path.exists(backup_dir):
            raise Exception(f"Diretório {backup_dir} não encontrado")
        
        # Lista todos os arquivos .txt e .json no diretório (suporta ambos os formatos)
        backup_files = [f for f in os.listdir(backup_dir) if f.endswith(('.txt', '.json'))]
        total_files = len(backup_files)
        
        for filename in backup_files:
            file_path = os.path.join(backup_dir, filename)
            
            try:
                # Extrai data do backup do nome do diretório
                backup_date_str = os.path.basename(backup_dir).replace('backup_', '')
                backup_date = datetime.strptime(backup_date_str, '%Y-%m-%d')
                backup_date = timezone.make_aware(backup_date)
                
                # Processa arquivo
                parsed_data = self.parser.parse_config_file(file_path)
                self.parser.save_to_database(parsed_data, backup_date)
                
                processed_files += 1
                
            except Exception as e:
                error_msg = f"Erro ao processar {filename}: {str(e)}"
                errors.append(error_msg)
        
        return processed_files, total_files, errors