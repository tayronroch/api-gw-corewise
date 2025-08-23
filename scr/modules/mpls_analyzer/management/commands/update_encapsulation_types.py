from django.core.management.base import BaseCommand
from modules.mpls_analyzer.models import Vpn


class Command(BaseCommand):
    help = 'Atualiza os tipos de encapsulamento para VPNs existentes'

    def handle(self, *args, **options):
        vpns = Vpn.objects.all()
        updated_count = 0
        
        self.stdout.write(f"🔄 Processando {vpns.count()} VPNs...")
        
        for vpn in vpns:
            old_type = vpn.encapsulation_type
            new_type = self._determine_encapsulation_type(vpn.encapsulation)
            
            if old_type != new_type:
                vpn.encapsulation_type = new_type
                vpn.save(update_fields=['encapsulation_type'])
                updated_count += 1
                
                self.stdout.write(f"✅ VPN {vpn.vpn_id}: {old_type} → {new_type} (encap: {vpn.encapsulation})")
        
        self.stdout.write(
            self.style.SUCCESS(f"✅ Processamento concluído! {updated_count} VPNs atualizadas.")
        )
    
    def _determine_encapsulation_type(self, encapsulation):
        """Determina o tipo de encapsulamento baseado no valor do campo encapsulation"""
        if not encapsulation:
            return 'untagged'
        
        encap_lower = encapsulation.lower()
        
        # Se contém qinq explícito
        if 'qinq' in encap_lower:
            return 'qinq'
        
        # Se tem múltiplas VLANs (espaçadas ou separadas por hífen)
        if ' ' in encapsulation or '-' in encapsulation:
            # Verifica se são números (VLANs)
            parts = encapsulation.replace('-', ' ').split()
            if len(parts) > 1 and all(part.isdigit() for part in parts):
                return 'qinq'
        
        # Se contém vlan explícito ou é um número simples
        if 'vlan' in encap_lower or encapsulation.isdigit():
            return 'vlan_tagged'
        
        # Se contém apenas números separados por vírgula
        if ',' in encapsulation:
            parts = [p.strip() for p in encapsulation.split(',')]
            if all(part.isdigit() for part in parts):
                return 'vlan_tagged' if len(parts) == 1 else 'qinq'
        
        # Padrões específicos
        vlan_patterns = ['dot1q', 'vlan', 'tagged']
        if any(pattern in encap_lower for pattern in vlan_patterns):
            return 'vlan_tagged'
        
        return 'untagged'