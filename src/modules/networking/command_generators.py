"""
Classes para gerar comandos de configuração de rede
Baseado na lógica do l2vpn-master para dispositivos Nokia/Alcatel-Lucent
"""
import logging
from typing import List, Dict, Any
from .models import L2VPNConfiguration, BGPConfiguration, OSPFConfiguration

logger = logging.getLogger(__name__)


class BaseCommandGenerator:
    """Classe base para geradores de comando"""
    
    def __init__(self):
        self.commands = []
    
    def add_command(self, command: str):
        """Adiciona comando à lista"""
        if command.strip():
            self.commands.append(command.strip())
    
    def add_commands(self, commands: List[str]):
        """Adiciona lista de comandos"""
        for cmd in commands:
            self.add_command(cmd)
    
    def get_commands(self) -> List[str]:
        """Retorna lista de comandos gerados"""
        return self.commands.copy()
    
    def clear(self):
        """Limpa lista de comandos"""
        self.commands.clear()


class L2VPNCommandGenerator(BaseCommandGenerator):
    """
    Gerador de comandos L2VPN VPWS para dispositivos Nokia/Alcatel-Lucent
    Baseado na lógica do l2vpn-master
    """
    
    def generate_pe_commands(self, config: L2VPNConfiguration, pe_side: str) -> str:
        """
        Gera comandos para um lado do L2VPN (PE1 ou PE2) exatamente como no Flask original
        pe_side: 'pe1' ou 'pe2'
        Retorna string com comandos completos, igual ao l2vpn-master
        """
        
        if pe_side == 'pe1':
            mode = config.pe1_mode
            vpws_group = config.pe1_vpws_group_name
            vpn_id = config.pe1_vpn_id
            neighbor_ip = config.pe1_neighbor_ip
            pw_id = config.pe1_pw_id
            interface = config.pe1_access_interface
            dot1q = config.pe1_dot1q
            pw_vlan = config.pe1_pw_vlan
            neighbor_targeted = config.pe1_neighbor_targeted_ip
        else:  # pe2
            mode = config.pe2_mode
            vpws_group = config.pe2_vpws_group_name
            vpn_id = config.pe2_vpn_id
            neighbor_ip = config.pe2_neighbor_ip
            pw_id = config.pe2_pw_id
            interface = config.pe2_access_interface
            dot1q = config.pe2_dot1q
            pw_vlan = config.pe2_pw_vlan
            neighbor_targeted = config.pe2_neighbor_targeted_ip
        
        logger.info(f"Gerando comandos L2VPN para {pe_side.upper()} - Modo: {mode}")
        
        # Gerar comandos exatamente como no Flask l2vpn-master
        if mode == "qinq":
            commands = f"""
config
mpls l2vpn vpws-group {vpws_group} vpn {vpn_id} qinq
neighbor {neighbor_ip}
pw-type vlan {pw_vlan}
pw-load-balance flow-label both
pw-id {pw_id}
exit
access-interface {interface}
encapsulation dot1q {dot1q}
top
mpls ldp lsr-id loopback-0 neighbor targeted {neighbor_targeted}
top
commit
exit
exit
"""
        elif mode == "vlan-selective":
            # VLAN-Selective (Access-Raw)
            commands = f"""
config
mpls l2vpn vpws-group {vpws_group} vpn {vpn_id} neighbor {neighbor_ip}
pw-type ethernet
pw-load-balance flow-label both
pw-id {pw_id}
exit
access-interface {interface}
top
mpls ldp lsr-id loopback-0 neighbor targeted {neighbor_targeted}
top
commit
exit
exit
"""
        elif mode == "access":
            commands = f"""
config
mpls l2vpn vpws-group {vpws_group} vpn {vpn_id} neighbor {neighbor_ip}
pw-type vlan {pw_vlan}
pw-load-balance flow-label both
pw-id {pw_id}
exit
access-interface {interface}
top
mpls ldp lsr-id loopback-0 neighbor targeted {neighbor_targeted}
top
commit
exit
exit
"""
        else:
            # Modo padrão (dot1q normal)
            commands = f"""
config
mpls l2vpn vpws-group {vpws_group} vpn {vpn_id} neighbor {neighbor_ip}
pw-type vlan {pw_vlan}
pw-load-balance flow-label both
pw-id {pw_id}
exit
access-interface {interface}
dot1q {dot1q}
top
mpls ldp lsr-id loopback-0 neighbor targeted {neighbor_targeted}
top
commit
exit
exit
"""
        
        logger.info(f"Comandos gerados para {pe_side.upper()}")
        
        return commands.strip()


class BGPCommandGenerator(BaseCommandGenerator):
    """
    Gerador de comandos BGP para dispositivos Nokia/Alcatel-Lucent
    Baseado na lógica do l2vpn-master
    """
    
    def generate_bgp_commands(self, config: BGPConfiguration) -> List[str]:
        """Gera comandos BGP para o roteador"""
        self.clear()
        
        import ipaddress
        
        # Calcular IPs das subnets
        try:
            v4_network = ipaddress.IPv4Network(config.subnet_v4, strict=False)
            v6_network = ipaddress.IPv6Network(config.subnet_v6, strict=False)
            
            v4_hosts = list(v4_network.hosts())
            v6_hosts = list(v6_network.hosts()) 
            
            v4_local = str(v4_hosts[0]) if v4_hosts else str(v4_network.network_address)
            v4_peer = str(v4_hosts[1]) if len(v4_hosts) > 1 else str(v4_hosts[0])
            
            v6_local = str(v6_hosts[0]) if v6_hosts else str(v6_network.network_address)
            v6_peer = str(v6_hosts[1]) if len(v6_hosts) > 1 else str(v6_hosts[0])
            
        except Exception as e:
            logger.error(f"Erro ao calcular IPs: {e}")
            raise
        
        logger.info(f"Gerando comandos BGP para cliente {config.client_name} - ASN {config.client_asn}")
        
        # Entrar em modo de configuração
        self.add_command("configure")
        
        # Configurar interface VLAN
        self.add_command("router interface")
        self.add_command(f"interface \"vlan-{config.vlan}\" create")
        self.add_command(f"description \"BGP Client {config.client_name}\"")
        self.add_command(f"address {v4_local}/{v4_network.prefixlen}")
        self.add_command(f"ipv6 address {v6_local}/{v6_network.prefixlen}")
        self.add_command("no shutdown")
        self.add_command("exit")
        self.add_command("exit")
        
        # Configurar VLAN na porta
        self.add_command("service")
        self.add_command(f"ies {config.vlan} customer 1 create")
        self.add_command(f"description \"BGP Service for {config.client_name}\"")
        self.add_command(f"interface \"vlan-{config.vlan}\" create")
        self.add_command(f"address {v4_local}/{v4_network.prefixlen}")
        self.add_command(f"ipv6 address {v6_local}/{v6_network.prefixlen}")
        self.add_command("exit")
        self.add_command(f"sap 1/1/1:{config.vlan} create")
        self.add_command(f"description \"Access port for {config.client_name}\"")
        self.add_command("exit")
        self.add_command("no shutdown")
        self.add_command("exit")
        self.add_command("exit")
        
        # Configurar BGP
        self.add_command("router")
        self.add_command("bgp")
        
        # Configurar neighbor IPv4
        self.add_command(f"group \"client-{config.client_name}-v4\"")
        self.add_command("type external")
        self.add_command(f"peer-as {config.client_asn}")
        self.add_command("exit")
        
        self.add_command(f"neighbor {v4_peer}")
        self.add_command(f"group \"client-{config.client_name}-v4\"")
        self.add_command("description f\"BGP IPv4 - {config.client_name}\"")
        self.add_command("no shutdown")
        self.add_command("exit")
        
        # Configurar neighbor IPv6
        self.add_command(f"group \"client-{config.client_name}-v6\"")
        self.add_command("type external")
        self.add_command(f"peer-as {config.client_asn}")
        self.add_command("family ipv6")
        self.add_command("exit")
        
        self.add_command(f"neighbor {v6_peer}")
        self.add_command(f"group \"client-{config.client_name}-v6\"")
        self.add_command(f"description \"BGP IPv6 - {config.client_name}\"")
        self.add_command("no shutdown")
        self.add_command("exit")
        
        # Configurar policy para anunciar redes do cliente
        client_v4_net = ipaddress.IPv4Network(config.client_network_v4, strict=False)
        client_v6_net = ipaddress.IPv6Network(config.client_network_v6, strict=False)
        
        self.add_command("exit")  # sair de bgp
        
        # Configurar rotas estáticas para as redes do cliente
        self.add_command(f"static-route {client_v4_net.network_address}/{client_v4_net.prefixlen} next-hop {v4_peer}")
        self.add_command(f"ipv6 static-route {client_v6_net.network_address}/{client_v6_net.prefixlen} next-hop {v6_peer}")
        
        self.add_command("exit")  # sair de router
        
        # Sair do modo de configuração
        self.add_command("exit all")
        
        # Commit das configurações
        self.add_command("admin save")
        
        logger.info(f"Gerados {len(self.commands)} comandos BGP")
        
        return self.get_commands()


class OSPFCommandGenerator(BaseCommandGenerator):
    """
    Gerador de comandos OSPF para dispositivos Nokia/Alcatel-Lucent
    Baseado na lógica do l2vpn-master
    """
    
    def generate_ospf_commands(self, config: OSPFConfiguration) -> List[str]:
        """Gera comandos OSPF para o roteador"""
        self.clear()
        
        logger.info(f"Gerando comandos OSPF - Process ID: {config.process_id}, Router ID: {config.router_id}")
        
        # Entrar em modo de configuração
        self.add_command("configure")
        
        # Configurar OSPF
        self.add_command("router")
        self.add_command("ospf")
        
        # Configurar router-id se especificado
        if config.router_id and config.router_id != config.router_ip:
            self.add_command(f"router-id {config.router_id}")
        
        # Configurar área
        self.add_command(f"area {config.area_id}")
        
        # Configurar interface no OSPF
        if config.interface.startswith('loopback'):
            # Interface loopback
            self.add_command(f"interface \"{config.interface}\" passive")
        else:
            # Interface física
            self.add_command(f"interface \"{config.interface}\"")
            
        # Configurar custo se especificado
        if config.cost and config.cost != 100:  # 100 é o padrão
            self.add_command(f"metric {config.cost}")
            
        self.add_command("exit")  # sair da interface
        self.add_command("exit")  # sair da área
        
        # Habilitar OSPF
        self.add_command("no shutdown")
        
        self.add_command("exit")  # sair de ospf
        self.add_command("exit")  # sair de router
        
        # Verificar se precisa configurar a interface física
        if not config.interface.startswith('loopback'):
            self.add_command("router interface")
            self.add_command(f"interface \"{config.interface}\"")
            self.add_command(f"description \"OSPF Interface - Process {config.process_id}\"")
            # Não configurar IP aqui pois já deve estar configurado
            self.add_command("no shutdown")
            self.add_command("exit")
            self.add_command("exit")
        
        # Sair do modo de configuração
        self.add_command("exit all")
        
        # Commit das configurações
        self.add_command("admin save")
        
        logger.info(f"Gerados {len(self.commands)} comandos OSPF")
        
        return self.get_commands()


class CommitCommandGenerator(BaseCommandGenerator):
    """
    Gerador de comandos para commit de configurações
    Baseado no l2vpn-master
    """
    
    def generate_commit_commands(self) -> List[str]:
        """Gera comandos para salvar/commit configurações"""
        self.clear()
        
        # Comandos de commit para Nokia/Alcatel-Lucent
        self.add_commands([
            "admin save",
            "show system information",
            "admin display-config"
        ])
        
        return self.get_commands()
    
    def generate_rollback_commands(self) -> List[str]:
        """Gera comandos para rollback de configurações"""
        self.clear()
        
        # Comandos de rollback
        self.add_commands([
            "admin revert",
            "show system information"
        ])
        
        return self.get_commands()


class ValidationCommandGenerator(BaseCommandGenerator):
    """
    Gerador de comandos para validação de configurações
    """
    
    def generate_validation_commands(self, config_type: str) -> List[str]:
        """
        Gera comandos de validação baseado no tipo de configuração
        config_type: 'l2vpn', 'bgp', 'ospf'
        """
        self.clear()
        
        # Comandos básicos de validação
        basic_commands = [
            "show system information",
            "show router interface",
            "show log"
        ]
        
        # Comandos específicos por tipo
        if config_type == 'l2vpn':
            specific_commands = [
                "show service vpls",
                "show service sdp",
                "show service sap",
                "show router ldp session"
            ]
        elif config_type == 'bgp':
            specific_commands = [
                "show router bgp summary", 
                "show router bgp neighbor",
                "show router route-table",
                "show service ies"
            ]
        elif config_type == 'ospf':
            specific_commands = [
                "show router ospf neighbor",
                "show router ospf database",
                "show router ospf interface",
                "show router ospf area"
            ]
        else:
            specific_commands = []
        
        self.add_commands(basic_commands)
        self.add_commands(specific_commands)
        
        return self.get_commands()


# Factory para criar geradores
class CommandGeneratorFactory:
    """Factory para criar instâncias de geradores de comando"""
    
    @staticmethod
    def create_generator(config_type: str) -> BaseCommandGenerator:
        """
        Cria gerador apropriado baseado no tipo de configuração
        config_type: 'l2vpn', 'bgp', 'ospf', 'commit', 'validation'
        """
        generators = {
            'l2vpn': L2VPNCommandGenerator,
            'bgp': BGPCommandGenerator,
            'ospf': OSPFCommandGenerator,
            'commit': CommitCommandGenerator,
            'validation': ValidationCommandGenerator
        }
        
        generator_class = generators.get(config_type)
        if not generator_class:
            raise ValueError(f"Tipo de gerador não suportado: {config_type}")
            
        return generator_class()