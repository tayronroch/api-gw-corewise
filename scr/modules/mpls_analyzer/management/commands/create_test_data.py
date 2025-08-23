from django.core.management.base import BaseCommand
from django.utils import timezone
from modules.mpls_analyzer.models import Equipment, MplsConfiguration, VpwsGroup, Vpn, Interface, LagMember, CustomerService


class Command(BaseCommand):
    help = 'Cria dados de teste para demonstrar as funcionalidades aprimoradas'

    def handle(self, *args, **options):
        self.stdout.write("🔄 Criando dados de teste...")
        
        # Criar ou obter equipamento de teste
        equipment, created = Equipment.objects.get_or_create(
            name='MA-CANABRAVA-PE01',
            defaults={
                'ip_address': '10.254.254.47',
                'location': 'MA-CANABRAVA',
                'equipment_type': 'PE',
                'last_backup': timezone.now()
            }
        )
        self.stdout.write(f"📡 Equipamento: {equipment.name} ({'criado' if created else 'existente'})")
        
        # Limpar configurações antigas deste equipamento para teste
        old_configs = MplsConfiguration.objects.filter(equipment=equipment)
        if old_configs.exists():
            self.stdout.write(f"🧹 Removendo {old_configs.count()} configurações antigas...")
            old_configs.delete()
        
        # Criar nova configuração
        mpls_config = MplsConfiguration.objects.create(
            equipment=equipment,
            backup_date=timezone.now(),
            raw_config="# Configuração de teste para demonstrar funcionalidades aprimoradas"
        )
        self.stdout.write(f"📋 Configuração MPLS criada: {mpls_config.id}")
        
        # Criar interfaces de teste
        self.stdout.write("\n📡 Criando interfaces de teste...")
        
        # Interface física de cliente
        interface_phys = Interface.objects.create(
            mpls_config=mpls_config,
            name='ten-gigabit-ethernet-1/1/4',
            description='CUSTOMER-ISP-ULTRANET-L2L-VL209-210',
            interface_type='physical',
            speed='10G',
            is_customer_interface=True
        )
        self.stdout.write(f"   • {interface_phys.name}: {interface_phys.description}")
        
        # LAG de cliente
        interface_lag = Interface.objects.create(
            mpls_config=mpls_config,
            name='lag-11',
            description='AGG-L2L-AS262274-INFOWEB-R1-PHB',
            interface_type='lag',
            is_customer_interface=True
        )
        self.stdout.write(f"   • {interface_lag.name}: {interface_lag.description}")
        
        # Membros do LAG
        LagMember.objects.create(
            lag_interface=interface_lag,
            member_interface_name='ten-gigabit-ethernet-1/1/5'
        )
        LagMember.objects.create(
            lag_interface=interface_lag,
            member_interface_name='ten-gigabit-ethernet-1/1/6'
        )
        self.stdout.write(f"     Membros: ten-gigabit-ethernet-1/1/5, ten-gigabit-ethernet-1/1/6")
        
        # Criar grupos VPWS e VPNs de teste
        self.stdout.write("\n🆔 Criando VPNs de teste...")
        
        # Grupo 1: PI-PARNAIBA-PE01
        vpws_group1 = VpwsGroup.objects.create(
            mpls_config=mpls_config,
            group_name='PI-PARNAIBA-PE01'
        )
        
        # VPN 3502 - QinQ
        vpn_3502 = Vpn.objects.create(
            vpws_group=vpws_group1,
            vpn_id=3502,
            description='',
            neighbor_ip='10.254.254.29',
            pw_type='vlan',
            pw_id=3502,
            encapsulation='qinq:209 210',
            encapsulation_type='qinq',
            access_interface='ten-gigabit-ethernet-1/1/4'
        )
        self.stdout.write(f"   • VPN {vpn_3502.vpn_id}: {vpn_3502.encapsulation} ({vpn_3502.encapsulation_type})")
        
        # VPN 3651 - VLAN Tagged
        vpn_3651 = Vpn.objects.create(
            vpws_group=vpws_group1,
            vpn_id=3651,
            description='',
            neighbor_ip='10.254.254.29',
            pw_type='vlan',
            pw_id=3651,
            encapsulation='vlan:651',
            encapsulation_type='vlan_tagged',
            access_interface='lag-11'
        )
        self.stdout.write(f"   • VPN {vpn_3651.vpn_id}: {vpn_3651.encapsulation} ({vpn_3651.encapsulation_type})")
        
        # Grupo 2: PI-TERESINA-PICARRA-PE00
        vpws_group2 = VpwsGroup.objects.create(
            mpls_config=mpls_config,
            group_name='PI-TERESINA-PICARRA-PE00'
        )
        
        # VPN 634 - VLAN Tagged
        vpn_634 = Vpn.objects.create(
            vpws_group=vpws_group2,
            vpn_id=634,
            description='LINK-MULTILINKTUTOIA-TSA-LAG02',
            neighbor_ip='10.254.254.0',
            pw_type='vlan',
            pw_id=634,
            encapsulation='vlan:634',
            encapsulation_type='vlan_tagged',
            access_interface='lag-10'
        )
        self.stdout.write(f"   • VPN {vpn_634.vpn_id}: {vpn_634.encapsulation} ({vpn_634.encapsulation_type})")
        
        # Criar serviços de clientes
        self.stdout.write("\n👥 Criando serviços de clientes...")
        
        customer_ultranet = CustomerService.objects.create(
            name='ULTRANET',
            vpn=vpn_3502,
            service_type='vpn',
            bandwidth='10G'
        )
        self.stdout.write(f"   • Cliente: {customer_ultranet.name} - VPN {vpn_3502.vpn_id}")
        
        customer_infoweb = CustomerService.objects.create(
            name='INFOWEB',
            vpn=vpn_3651,
            service_type='data',
            bandwidth='1G'
        )
        self.stdout.write(f"   • Cliente: {customer_infoweb.name} - VPN {vpn_3651.vpn_id}")
        
        customer_multilink = CustomerService.objects.create(
            name='MULTILINKTUTOIA',
            vpn=vpn_634,
            service_type='internet',
            bandwidth='100M'
        )
        self.stdout.write(f"   • Cliente: {customer_multilink.name} - VPN {vpn_634.vpn_id}")
        
        self.stdout.write(
            self.style.SUCCESS("\n✅ Dados de teste criados com sucesso!")
        )
        self.stdout.write("\n🧪 TESTE AS FUNCIONALIDADES:")
        self.stdout.write("1. Busca por VPN ID: http://localhost:8000/search/?q=3502")
        self.stdout.write("2. Busca por cliente: http://localhost:8000/search/?q=ULTRANET")
        self.stdout.write("3. API VPN Report: http://localhost:8000/api/vpn-report/?vpn_id=3502")
        self.stdout.write("4. API Interface Report: http://localhost:8000/api/customer-interface-report/?equipment=MA-CANABRAVA-PE01")