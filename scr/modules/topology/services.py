# topology/services.py
import requests
import json
from django.conf import settings
from typing import Dict, List, Any
from .models import Equipment, Link, LinkTrafficHistory
import logging

logger = logging.getLogger(__name__)

def calculate_percentile95(link):
    """Calcula o percentil 95 do tráfego de um link"""
    history = LinkTrafficHistory.objects.filter(link=link).order_by('-timestamp')
    values = list(history.values_list('traffic_in_bps', flat=True))
    if not values:
        return 0
    values.sort()
    idx = int(0.95 * len(values)) - 1
    percentile_95 = values[idx] if idx >= 0 else values[0]
    return percentile_95

class ZabbixService:
    def __init__(self):
        self.url = getattr(settings, 'ZABBIX_URL', 'http://localhost/zabbix/api_jsonrpc.php')
        self.username = getattr(settings, 'ZABBIX_USERNAME', 'admin')
        self.password = getattr(settings, 'ZABBIX_PASSWORD', 'zabbix')
        self.auth_token = None
    
    def authenticate(self) -> bool:
        """Autentica no Zabbix e obtém token"""
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "user.login",
                "params": {
                    "user": self.username,
                    "password": self.password
                },
                "id": 1
            }
            
            response = requests.post(self.url, json=payload, timeout=30)
            result = response.json()
            
            if 'result' in result:
                self.auth_token = result['result']
                logger.info("Zabbix authentication successful")
                return True
            else:
                logger.error(f"Zabbix auth error: {result.get('error', 'Unknown error')}")
                return False
                
        except Exception as e:
            logger.error(f"Zabbix authentication failed: {e}")
            return False
    
    def get_hosts(self) -> List[Dict]:
        """Busca todos os hosts do Zabbix"""
        if not self.auth_token and not self.authenticate():
            return []
        
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "host.get",
                "params": {
                    "output": ["hostid", "host", "name", "status"],
                    "selectInterfaces": ["interfaceid", "ip", "port", "type"],
                    "selectGroups": ["groupid", "name"],
                    "filter": {
                        "status": 0  # Apenas hosts ativos
                    }
                },
                "auth": self.auth_token,
                "id": 2
            }
            
            response = requests.post(self.url, json=payload, timeout=30)
            result = response.json()
            
            if 'result' in result:
                return result['result']
            else:
                logger.error(f"Failed to get hosts: {result.get('error', 'Unknown error')}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting hosts: {e}")
            return []
    
    def get_network_interfaces(self, hostid: str) -> List[Dict]:
        """Busca interfaces de rede de um host específico"""
        if not self.auth_token:
            return []
        
        try:
            payload = {
                "jsonrpc": "2.0",
                "method": "item.get",
                "params": {
                    "output": ["itemid", "name", "key_", "lastvalue", "units"],
                    "hostids": hostid,
                    "search": {
                        "key_": "net.if"
                    },
                    "searchWildcardsEnabled": True
                },
                "auth": self.auth_token,
                "id": 3
            }
            
            response = requests.post(self.url, json=payload, timeout=30)
            result = response.json()
            
            if 'result' in result:
                return result['result']
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            return []

class TopologyService:
    def __init__(self):
        self.zabbix = ZabbixService()
    
    def sync_from_zabbix(self) -> bool:
        """Sincroniza equipamentos e links do Zabbix"""
        try:
            hosts = self.zabbix.get_hosts()
            
            for host in hosts:
                # Criar/atualizar equipamento
                if host.get('interfaces'):
                    ip_address = host['interfaces'][0].get('ip', '127.0.0.1')
                    
                    equipment, created = Equipment.objects.get_or_create(
                        ip_address=ip_address,
                        defaults={
                            'name': host.get('name', host.get('host', 'Unknown')),
                            'description': f"Zabbix Host ID: {host['hostid']}"
                        }
                    )
                    
                    if created:
                        logger.info(f"Created equipment: {equipment.name}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error syncing from Zabbix: {e}")
            return False
    
    def get_topology_data(self) -> Dict[str, Any]:
        """Retorna dados de topologia formatados para o frontend"""
        
        # Sincronizar dados do Zabbix primeiro
        self.sync_from_zabbix()
        
        # Buscar equipamentos
        equipments = Equipment.objects.all()
        
        nodes = []
        for eq in equipments:
            nodes.append({
                "id": str(eq.id),
                "label": eq.name,
                "type": "switch",  # ou detectar tipo baseado no nome/grupo
                "ip": eq.ip_address,
                "description": eq.description,
                "status": "online",  # buscar do Zabbix se necessário
                "position": {
                    "x": hash(eq.name) % 800,  # posição aleatória baseada no nome
                    "y": hash(eq.ip_address) % 600
                }
            })
        
        # Buscar links
        links = Link.objects.all()
        
        edges = []
        for link in links:
            # Buscar tráfego mais recente
            latest_traffic = LinkTrafficHistory.objects.filter(link=link).first()
            
            traffic_in = 0
            traffic_out = 0
            if latest_traffic:
                traffic_in = latest_traffic.traffic_in_bps
                traffic_out = latest_traffic.traffic_out_bps
            
            edges.append({
                "id": str(link.id),
                "source": str(link.source.id),
                "target": str(link.target.id),
                "bandwidth": f"{link.capacity_mbps}Mbps" if link.capacity_mbps else "Unknown",
                "traffic_in": self._format_bandwidth(traffic_in),
                "traffic_out": self._format_bandwidth(traffic_out),
                "utilization": self._calculate_utilization(traffic_in + traffic_out, link.capacity_mbps),
                "status": "active"
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "last_update": "2025-01-02T18:00:00Z"
        }
    
    def _format_bandwidth(self, bps: int) -> str:
        """Formata bandwidth em unidades legíveis"""
        if bps >= 1_000_000_000:
            return f"{bps / 1_000_000_000:.2f}Gbps"
        elif bps >= 1_000_000:
            return f"{bps / 1_000_000:.2f}Mbps"
        elif bps >= 1_000:
            return f"{bps / 1_000:.2f}Kbps"
        else:
            return f"{bps}bps"
    
    def _calculate_utilization(self, current_bps: int, capacity_mbps: int) -> float:
        """Calcula utilização do link em porcentagem"""
        if not capacity_mbps:
            return 0.0
        
        capacity_bps = capacity_mbps * 1_000_000
        if capacity_bps <= 0:
            return 0.0
        
        utilization = (current_bps / capacity_bps) * 100
        return min(utilization, 100.0)

# Função para simular dados quando Zabbix não disponível
def get_mock_topology_data() -> Dict[str, Any]:
    """Dados simulados para desenvolvimento/teste"""
    return {
        "nodes": [
            {
                "id": "sw1",
                "label": "Core-Switch-SP",
                "type": "switch",
                "ip": "192.168.1.1",
                "status": "online",
                "position": {"x": 400, "y": 100}
            },
            {
                "id": "sw2", 
                "label": "Distrib-Switch-RJ",
                "type": "switch",
                "ip": "192.168.1.2", 
                "status": "online",
                "position": {"x": 600, "y": 300}
            },
            {
                "id": "sw3",
                "label": "Access-Switch-BH", 
                "type": "switch",
                "ip": "192.168.1.3",
                "status": "warning",
                "position": {"x": 200, "y": 400}
            },
            {
                "id": "rt1",
                "label": "Router-Core-BSB",
                "type": "router", 
                "ip": "192.168.1.10",
                "status": "online",
                "position": {"x": 400, "y": 500}
            }
        ],
        "edges": [
            {
                "id": "e1",
                "source": "sw1", 
                "target": "sw2",
                "bandwidth": "10Gbps",
                "traffic_in": "3.2Gbps",
                "traffic_out": "2.8Gbps", 
                "utilization": 60.0,
                "status": "active"
            },
            {
                "id": "e2",
                "source": "sw2",
                "target": "sw3", 
                "bandwidth": "1Gbps",
                "traffic_in": "450Mbps",
                "traffic_out": "380Mbps",
                "utilization": 83.0,
                "status": "active"
            },
            {
                "id": "e3", 
                "source": "sw1",
                "target": "rt1",
                "bandwidth": "40Gbps", 
                "traffic_in": "12.5Gbps",
                "traffic_out": "8.7Gbps",
                "utilization": 53.0,
                "status": "active"
            }
        ],
        "last_update": "2025-01-02T18:00:00Z"
    }
