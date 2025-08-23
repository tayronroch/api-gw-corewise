"""
Cliente SSH para comunicação com dispositivos de rede
Baseado na lógica do utils.py do l2vpn-master
"""
import paramiko
import time
import logging
from typing import List, Optional, Dict, Any
from contextlib import contextmanager
import threading

logger = logging.getLogger(__name__)

# Lock global para evitar conexões SSH simultâneas problemáticas
ssh_lock = threading.Lock()


class SSHNetworkClient:
    """
    Cliente SSH otimizado para dispositivos de rede Nokia/Alcatel-Lucent
    Baseado na implementação do l2vpn-master
    """
    
    def __init__(self, hostname: str, username: str, password: str, 
                 port: int = 22, timeout: int = 30):
        """
        Inicializa cliente SSH
        
        Args:
            hostname: IP ou hostname do dispositivo
            username: Username para autenticação
            password: Password para autenticação  
            port: Porta SSH (padrão 22)
            timeout: Timeout para conexões (padrão 30s)
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        
        self.ssh_client: Optional[paramiko.SSHClient] = None
        self.channel: Optional[paramiko.Channel] = None
        self.connected = False
        
        logger.info(f"SSH Client criado para {hostname}:{port}")
    
    def connect(self) -> bool:
        """
        Estabelece conexão SSH com o dispositivo
        
        Returns:
            bool: True se conexão foi estabelecida com sucesso
        """
        try:
            with ssh_lock:
                logger.info(f"Conectando SSH em {self.hostname}...")
                
                # Criar cliente SSH
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Conectar
                self.ssh_client.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
                
                # Criar shell interativo
                self.channel = self.ssh_client.invoke_shell(
                    term='vt100',
                    width=200,
                    height=50
                )
                
                # Aguardar prompt inicial
                time.sleep(2)
                
                # Limpar buffer inicial
                if self.channel.recv_ready():
                    initial_output = self.channel.recv(4096).decode('utf-8', errors='ignore')
                    logger.debug(f"Prompt inicial: {initial_output}")
                
                # Configurar terminal
                self._send_command("environment no more", wait_for_prompt=True)
                
                self.connected = True
                logger.info(f"Conexão SSH estabelecida com {self.hostname}")
                return True
                
        except paramiko.AuthenticationException:
            logger.error(f"Falha na autenticação SSH para {self.hostname}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"Erro SSH para {self.hostname}: {e}")
            return False
        except Exception as e:
            logger.error(f"Erro ao conectar SSH em {self.hostname}: {e}")
            return False
    
    def disconnect(self):
        """Fecha a conexão SSH"""
        try:
            if self.channel:
                self.channel.close()
                self.channel = None
                
            if self.ssh_client:
                self.ssh_client.close()
                self.ssh_client = None
                
            self.connected = False
            logger.info(f"Conexão SSH fechada com {self.hostname}")
            
        except Exception as e:
            logger.error(f"Erro ao fechar conexão SSH com {self.hostname}: {e}")
    
    def _send_command(self, command: str, wait_for_prompt: bool = True, 
                     timeout: int = 30) -> str:
        """
        Envia comando individual para o dispositivo
        
        Args:
            command: Comando a ser executado
            wait_for_prompt: Se deve aguardar prompt de retorno
            timeout: Timeout para o comando
            
        Returns:
            str: Output do comando
        """
        if not self.connected or not self.channel:
            raise Exception("SSH não conectado")
        
        try:
            logger.debug(f"Executando comando: {command}")
            
            # Enviar comando
            self.channel.send(command + '\n')
            time.sleep(0.5)
            
            if not wait_for_prompt:
                return ""
            
            # Aguardar resposta
            output = ""
            start_time = time.time()
            
            while True:
                if self.channel.recv_ready():
                    chunk = self.channel.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    
                    # Verificar se chegou ao prompt
                    if self._has_prompt(output):
                        break
                        
                # Verificar timeout
                if time.time() - start_time > timeout:
                    logger.warning(f"Timeout executando comando: {command}")
                    break
                    
                time.sleep(0.1)
            
            # Limpar prompt da saída
            output = self._clean_output(output, command)
            
            logger.debug(f"Output comando: {output[:200]}...")
            return output
            
        except Exception as e:
            logger.error(f"Erro executando comando '{command}': {e}")
            raise
    
    def _has_prompt(self, output: str) -> bool:
        """
        Verifica se o output contém um prompt típico do Nokia/ALU
        
        Args:
            output: Output para verificar
            
        Returns:
            bool: True se contém prompt
        """
        # Prompts comuns do Nokia/ALU
        prompts = [
            '*A:', '*B:', 'A:', 'B:',  # Prompts normais
            '(config)', '(service)',    # Prompts de configuração
            '#', '>', '$'               # Prompts gerais
        ]
        
        lines = output.strip().split('\n')
        if lines:
            last_line = lines[-1].strip()
            for prompt in prompts:
                if prompt in last_line:
                    return True
        return False
    
    def _clean_output(self, output: str, command: str) -> str:
        """
        Limpa o output removendo ecos e prompts
        
        Args:
            output: Output bruto
            command: Comando original
            
        Returns:
            str: Output limpo
        """
        lines = output.split('\n')
        cleaned_lines = []
        
        # Remover primeira linha se for eco do comando
        if lines and command.strip() in lines[0]:
            lines = lines[1:]
        
        # Remover última linha se for prompt
        if lines and self._has_prompt(lines[-1]):
            lines = lines[:-1]
        
        # Filtrar linhas vazias e caracteres de controle
        for line in lines:
            cleaned = line.strip()
            if cleaned and not cleaned.startswith('\x00'):
                cleaned_lines.append(cleaned)
        
        return '\n'.join(cleaned_lines)
    
    def execute_commands(self, commands: List[str]) -> str:
        """
        Executa lista de comandos sequencialmente
        
        Args:
            commands: Lista de comandos
            
        Returns:
            str: Output concatenado de todos os comandos
        """
        if not self.connected:
            raise Exception("SSH não conectado")
        
        all_output = []
        
        logger.info(f"Executando {len(commands)} comandos em {self.hostname}")
        
        for i, command in enumerate(commands, 1):
            try:
                output = self._send_command(command, wait_for_prompt=True, timeout=60)
                all_output.append(f"=== Comando {i}: {command} ===")
                all_output.append(output)
                all_output.append("")  # Linha em branco
                
                # Pausa entre comandos para evitar sobrecarga
                if i < len(commands):
                    time.sleep(0.5)
                    
            except Exception as e:
                error_msg = f"Erro no comando '{command}': {e}"
                logger.error(error_msg)
                all_output.append(f"=== ERRO no comando {i}: {command} ===")
                all_output.append(error_msg)
                all_output.append("")
                # Continuar com próximos comandos mesmo em caso de erro
        
        final_output = '\n'.join(all_output)
        logger.info(f"Execução concluída em {self.hostname} - {len(final_output)} chars de output")
        
        return final_output
    
    def execute_single_command(self, command: str, timeout: int = 30) -> str:
        """
        Executa um único comando
        
        Args:
            command: Comando a executar
            timeout: Timeout para o comando
            
        Returns:
            str: Output do comando
        """
        if not self.connected:
            raise Exception("SSH não conectado")
        
        return self._send_command(command, wait_for_prompt=True, timeout=timeout)
    
    def test_connectivity(self) -> Dict[str, Any]:
        """
        Testa conectividade básica com o dispositivo
        
        Returns:
            dict: Resultado do teste com informações do dispositivo
        """
        try:
            # Comandos básicos de teste
            version_output = self.execute_single_command("show version", timeout=15)
            uptime_output = self.execute_single_command("show system uptime", timeout=10)
            
            return {
                'success': True,
                'hostname': self.hostname,
                'version_info': version_output[:500],  # Primeiros 500 chars
                'uptime_info': uptime_output[:200],    # Primeiros 200 chars
                'connection_time': time.time()
            }
            
        except Exception as e:
            return {
                'success': False,
                'hostname': self.hostname,
                'error': str(e),
                'connection_time': time.time()
            }
    
    def __enter__(self):
        """Context manager entry"""
        if not self.connect():
            raise Exception(f"Falha ao conectar SSH em {self.hostname}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
        return False


# Context manager convenience function
@contextmanager
def ssh_connection(hostname: str, username: str, password: str, 
                  port: int = 22, timeout: int = 30):
    """
    Context manager conveniente para conexões SSH
    
    Args:
        hostname: IP ou hostname
        username: Username
        password: Password
        port: Porta SSH
        timeout: Timeout
        
    Yields:
        SSHNetworkClient: Cliente conectado
    """
    client = SSHNetworkClient(hostname, username, password, port, timeout)
    try:
        if not client.connect():
            raise Exception(f"Falha ao conectar SSH em {hostname}")
        yield client
    finally:
        client.disconnect()


class SSHConnectionPool:
    """
    Pool de conexões SSH para reutilização
    """
    
    def __init__(self, max_connections: int = 10):
        self.max_connections = max_connections
        self.connections: Dict[str, SSHNetworkClient] = {}
        self.lock = threading.Lock()
    
    def get_connection(self, hostname: str, username: str, password: str, 
                      port: int = 22, timeout: int = 30) -> SSHNetworkClient:
        """
        Obtém conexão do pool ou cria nova
        
        Returns:
            SSHNetworkClient: Cliente conectado
        """
        connection_key = f"{username}@{hostname}:{port}"
        
        with self.lock:
            # Verificar se já existe conexão ativa
            if connection_key in self.connections:
                client = self.connections[connection_key]
                if client.connected:
                    logger.debug(f"Reutilizando conexão SSH para {hostname}")
                    return client
                else:
                    # Remover conexão inativa
                    del self.connections[connection_key]
            
            # Criar nova conexão
            if len(self.connections) >= self.max_connections:
                # Remover conexão mais antiga
                oldest_key = next(iter(self.connections))
                self.connections[oldest_key].disconnect()
                del self.connections[oldest_key]
            
            # Criar e conectar novo cliente
            client = SSHNetworkClient(hostname, username, password, port, timeout)
            if client.connect():
                self.connections[connection_key] = client
                logger.info(f"Nova conexão SSH criada para {hostname}")
                return client
            else:
                raise Exception(f"Falha ao conectar SSH em {hostname}")
    
    def close_all(self):
        """Fecha todas as conexões do pool"""
        with self.lock:
            for client in self.connections.values():
                client.disconnect()
            self.connections.clear()
            logger.info("Todas as conexões SSH do pool foram fechadas")


# Instância global do pool
ssh_pool = SSHConnectionPool()


def execute_ssh_commands_with_pool(hostname: str, username: str, password: str,
                                 commands: List[str], port: int = 22, 
                                 timeout: int = 30) -> str:
    """
    Executa comandos SSH usando o pool de conexões
    
    Args:
        hostname: IP ou hostname
        username: Username  
        password: Password
        commands: Lista de comandos
        port: Porta SSH
        timeout: Timeout
        
    Returns:
        str: Output dos comandos
    """
    try:
        client = ssh_pool.get_connection(hostname, username, password, port, timeout)
        return client.execute_commands(commands)
    except Exception as e:
        logger.error(f"Erro executando comandos SSH em {hostname}: {e}")
        raise