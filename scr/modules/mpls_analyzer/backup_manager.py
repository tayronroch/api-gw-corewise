"""
Módulo integrado para gerenciamento de backups MPLS
Baseado no script easy-bkp-optimized.py original
"""
import paramiko
import json
import os
import time
from pathlib import Path
from django.conf import settings
from django.utils import timezone
from .models import Equipment, MplsConfiguration
from .network_scanner import NetworkScanner
import logging

logger = logging.getLogger(__name__)


class BackupManager:
    """Gerenciador de backups integrado ao Django"""
    
    def __init__(self):
        self.script_dir = Path(__file__).parent / 'scripts'
        self.backup_base_dir = self.script_dir / f"backup_{timezone.now().strftime('%Y-%m-%d')}"
        self.json_file = self.script_dir / "banco-de-dados.json"
        self.ssh_port = 5620
        
    def create_backup_directory(self):
        """Cria diretório de backup"""
        try:
            self.backup_base_dir.mkdir(exist_ok=True)
            logger.info(f"Diretório de backup criado: {self.backup_base_dir}")
            return True
        except Exception as e:
            logger.error(f"Erro ao criar diretório de backup: {e}")
            return False
    
    def backup_device_config(self, device_info, username=None, password=None):
        """Faz backup da configuração de um dispositivo"""
        try:
            username = username or os.environ.get("DEVICE_USERNAME", "login")
            password = password or os.environ.get("DEVICE_PASSWORD", "senha")
            
            device_name = device_info.get('name', 'unknown')
            device_ip = device_info.get('ip', '')
            
            if not device_ip:
                logger.warning(f"IP não encontrado para {device_name}")
                return False
            
            # Cria diretório do dispositivo
            device_dir = self.backup_base_dir / device_name
            device_dir.mkdir(exist_ok=True)
            
            # Conecta via SSH
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(device_ip, port=self.ssh_port, username=username, 
                         password=password, timeout=30)
            
            # Comandos para backup
            commands = [
                "show running-config",
                "show version",
                "show ip interface brief",
                "show ip route",
                "show mpls ldp neighbor",
                "show mpls l2vpn vc"
            ]
            
            config_data = {}
            
            for cmd in commands:
                try:
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
                    output = stdout.read().decode("utf-8", errors='ignore')
                    error = stderr.read().decode("utf-8", errors='ignore')
                    
                    if output.strip():
                        config_data[cmd] = output
                    if error.strip():
                        logger.warning(f"Comando '{cmd}' em {device_name} retornou erro: {error}")
                        
                except Exception as e:
                    logger.warning(f"Erro ao executar comando '{cmd}' em {device_name}: {e}")
            
            client.close()
            
            # Salva configuração bruta
            config_file = device_dir / "config_raw.txt"
            with open(config_file, 'w', encoding='utf-8') as f:
                for cmd, output in config_data.items():
                    f.write(f"=== {cmd} ===\n")
                    f.write(output)
                    f.write("\n\n")
            
            # Salva configuração estruturada
            structured_file = device_dir / "config_structured.json"
            structured_data = {
                "device_name": device_name,
                "device_ip": device_ip,
                "backup_date": timezone.now().isoformat(),
                "commands": config_data
            }
            
            with open(structured_file, 'w', encoding='utf-8') as f:
                json.dump(structured_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Backup de {device_name} concluído")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao fazer backup de {device_info.get('name', 'unknown')}: {e}")
            return False
    
    def backup_all_devices(self, username=None, password=None):
        """Faz backup de todos os dispositivos"""
        logger.info("Iniciando backup de todos os dispositivos")
        
        # Cria diretório de backup
        if not self.create_backup_directory():
            return False
        
        # Carrega lista de dispositivos
        if not self.json_file.exists():
            logger.error("Arquivo de banco de dados não encontrado")
            return False
        
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                devices = json.load(f)
        except Exception as e:
            logger.error(f"Erro ao carregar banco de dados: {e}")
            return False
        
        # Executa backup de cada dispositivo
        success_count = 0
        total_count = len(devices)
        
        for device in devices:
            if self.backup_device_config(device, username, password):
                success_count += 1
            
            # Pequena pausa entre dispositivos
            time.sleep(1)
        
        logger.info(f"Backup concluído: {success_count}/{total_count} dispositivos")
        return success_count, total_count
    
    def get_backup_status(self):
        """Retorna status dos backups"""
        if not self.backup_base_dir.exists():
            return {
                "status": "no_backup",
                "message": "Nenhum backup encontrado"
            }
        
        try:
            device_dirs = [d for d in self.backup_base_dir.iterdir() if d.is_dir()]
            total_devices = len(device_dirs)
            
            successful_backups = 0
            for device_dir in device_dirs:
                config_file = device_dir / "config_raw.txt"
                if config_file.exists() and config_file.stat().st_size > 0:
                    successful_backups += 1
            
            return {
                "status": "completed",
                "backup_date": self.backup_base_dir.name,
                "total_devices": total_devices,
                "successful_backups": successful_backups,
                "backup_directory": str(self.backup_base_dir)
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


def backup_all_devices_command(username=None, password=None):
    """Função para uso em comandos Django"""
    manager = BackupManager()
    return manager.backup_all_devices(username, password)


def get_backup_status_command():
    """Função para verificar status dos backups"""
    manager = BackupManager()
    return manager.get_backup_status()
