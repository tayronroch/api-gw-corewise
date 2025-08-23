"""
Módulo integrado para scan de rede MPLS
Baseado no script scan-network.py original
"""
import paramiko
import json
import os
import subprocess
import ipaddress
from pathlib import Path
from django.conf import settings
from django.utils import timezone
from .models import Equipment, MplsConfiguration
import logging

logger = logging.getLogger(__name__)


class NetworkScanner:
    """Scanner de rede integrado ao Django"""
    
    def __init__(self):
        self.network = "10.254.254.0/24"
        self.ssh_port = 5620
        self.script_dir = Path(__file__).parent / 'scripts'
        self.json_file = self.script_dir / "banco-de-dados.json"
        
    def scan_network(self, username=None, password=None):
        """Escaneia a rede e retorna hosts ativos"""
        logger.info(f"Escaneando rede {self.network}")
        
        try:
            # Usa variáveis de ambiente ou parâmetros
            username = username or os.environ.get("DEVICE_USERNAME", "login")
            password = password or os.environ.get("DEVICE_PASSWORD", "senha")
            
            # Executa nmap
            result = subprocess.run(
                ["nmap", "-p", str(self.ssh_port), "-n", "-oG", "-", self.network],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                logger.error(f"Erro no nmap: {result.stderr}")
                return []
            
            # Processa resultados
            active_hosts = []
            for line in result.stdout.splitlines():
                if "open" in line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) > 1:
                        ip = parts[1]
                        if self._is_valid_host_ip(ip):
                            active_hosts.append(ip)
            
            logger.info(f"Encontrados {len(active_hosts)} hosts ativos")
            return active_hosts
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout no scan da rede")
            return []
        except Exception as e:
            logger.error(f"Erro ao escanear rede: {e}")
            return []
    
    def _is_valid_host_ip(self, ip):
        """Verifica se o IP é válido para host"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (ip_obj.is_private and 
                   not ip.endswith(".0") and 
                   not ip.endswith(".255"))
        except:
            return False
    
    def collect_host_info(self, ip, username=None, password=None):
        """Coleta informações do host via SSH"""
        logger.info(f"Conectando ao host {ip}")
        
        try:
            username = username or os.environ.get("DEVICE_USERNAME", "login")
            password = password or os.environ.get("DEVICE_PASSWORD", "senha")
            
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=self.ssh_port, username=username, 
                         password=password, timeout=10)
            
            # Coleta hostname
            stdin, stdout, stderr = client.exec_command("show running-config hostname")
            hostname_output = stdout.read().decode("utf-8").strip()
            hostname = None
            for line in hostname_output.splitlines():
                if line.startswith("hostname"):
                    hostname = line.split()[1]
                    break
            
            # Coleta interfaces
            stdin, stdout, stderr = client.exec_command("show ip interface brief")
            interfaces_output = stdout.read().decode("utf-8").strip()
            interfaces = []
            for line in interfaces_output.splitlines():
                if "active" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        if parts[3] not in ["4000", "4001", "4002", "4003", "loopback-0", "100", "98"]:
                            interfaces.append({
                                "interface": parts[1], 
                                "ip": parts[3], 
                                "state": parts[-1]
                            })
            
            client.close()
            
            return {
                "name": hostname,
                "ip": ip,
                "interfaces": interfaces
            }
            
        except Exception as e:
            logger.error(f"Erro ao conectar ao host {ip}: {e}")
            return None
    
    def update_database_json(self, hosts_info):
        """Atualiza o arquivo JSON de banco de dados"""
        try:
            if self.json_file.exists():
                with open(self.json_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
            else:
                existing_data = []
            
            # Adiciona novos hosts e remove duplicatas
            for host_info in hosts_info:
                if host_info:
                    # Remove host existente com mesmo IP
                    existing_data = [h for h in existing_data if h.get('ip') != host_info['ip']]
                    existing_data.append(host_info)
            
            # Salva arquivo atualizado
            with open(self.json_file, 'w', encoding='utf-8') as f:
                json.dump(existing_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Banco JSON atualizado com {len(existing_data)} hosts")
            return existing_data
            
        except Exception as e:
            logger.error(f"Erro ao atualizar banco JSON: {e}")
            return []
    
    def scan_and_update(self, username=None, password=None):
        """Executa scan completo e atualiza banco"""
        logger.info("Iniciando scan completo da rede")
        
        # Escaneia rede
        active_hosts = self.scan_network(username, password)
        if not active_hosts:
            logger.warning("Nenhum host ativo encontrado")
            return []
        
        # Coleta informações dos hosts
        hosts_info = []
        for ip in active_hosts:
            host_info = self.collect_host_info(ip, username, password)
            if host_info:
                hosts_info.append(host_info)
                logger.info(f"Host {host_info['name']} ({ip}) processado")
        
        # Atualiza banco JSON
        self.update_database_json(hosts_info)
        
        logger.info(f"Scan concluído: {len(hosts_info)} hosts processados")
        return hosts_info


def scan_network_command(username=None, password=None):
    """Função para uso em comandos Django"""
    scanner = NetworkScanner()
    return scanner.scan_and_update(username, password)
