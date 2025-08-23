from django.core.management.base import BaseCommand
from django.utils import timezone
from modules.mpls_analyzer.parsers import MplsConfigParser
import json
import sys


class Command(BaseCommand):
    help = 'Processa um arquivo JSON de configuração DMOS e salva no banco de dados'

    def add_arguments(self, parser):
        parser.add_argument(
            'json_file',
            type=str,
            help='Caminho para o arquivo JSON de configuração'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Executa sem salvar no banco (apenas mostra o que seria processado)',
        )

    def handle(self, *args, **options):
        json_file = options['json_file']
        dry_run = options.get('dry_run', False)
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                json_content = f.read()
            
            self.stdout.write(f"📄 Processando arquivo: {json_file}")
            
            # Corrige JSON malformado se necessário
            json_content = self._fix_malformed_json(json_content)
            
            # Cria parser e processa
            parser = MplsConfigParser()
            parsed_data = parser.parse_device_json_text(json_content)
            
            # Mostra informações extraídas
            self.stdout.write("\n=== DADOS EXTRAÍDOS ===")
            self.stdout.write(f"🖥️  Equipamento: {parsed_data['equipment_name']}")
            if parsed_data.get('equipment_ip'):
                self.stdout.write(f"🔗 Loopback IP: {parsed_data['equipment_ip']}")
            
            # Interfaces de cliente
            customer_interfaces = parsed_data.get('customer_interfaces', [])
            if customer_interfaces:
                self.stdout.write(f"\n📡 Interfaces de clientes encontradas: {len(customer_interfaces)}")
                for iface in customer_interfaces:
                    self.stdout.write(f"   • {iface['interface']}: {iface['description']}")
            
            # LAGs de cliente
            customer_lags = parsed_data.get('customer_lags', [])
            if customer_lags:
                self.stdout.write(f"\n🔗 LAGs de clientes encontrados: {len(customer_lags)}")
                lag_members = parsed_data.get('lag_members', {})
                for lag in customer_lags:
                    members = lag_members.get(lag['interface'], [])
                    self.stdout.write(f"   • {lag['interface']}: {lag['description']}")
                    if members:
                        self.stdout.write(f"     Membros: {', '.join(members)}")
            
            # VPNs
            vpws_groups = parsed_data.get('vpws_groups', [])
            total_vpns = sum(len(group.get('vpns', [])) for group in vpws_groups)
            if total_vpns > 0:
                self.stdout.write(f"\n🆔 VPNs encontradas: {total_vpns}")
                for group in vpws_groups:
                    self.stdout.write(f"   📊 Grupo: {group['group_name']}")
                    for vpn in group.get('vpns', []):
                        encap_type = vpn.get('encapsulation_type', 'untagged')
                        self.stdout.write(f"      • VPN {vpn['vpn_id']} -> {vpn['neighbor_ip']}")
                        self.stdout.write(f"        Interface: {vpn['access_interface']}")
                        self.stdout.write(f"        Encapsulamento: {vpn['encapsulation']} ({encap_type})")
                        if vpn.get('description'):
                            self.stdout.write(f"        Descrição: {vpn['description']}")
            
            # Clientes identificados
            customers = parsed_data.get('description_customers', [])
            if customers:
                self.stdout.write(f"\n👥 Clientes identificados: {len(customers)}")
                for customer in customers:
                    self.stdout.write(f"   • {customer}")
            
            if not dry_run:
                self.stdout.write(f"\n💾 Salvando no banco de dados...")
                equipment = parser.save_to_database(parsed_data, timezone.now())
                self.stdout.write(
                    self.style.SUCCESS(f"✅ Configuração salva para equipamento: {equipment.name}")
                )
            else:
                self.stdout.write(f"\n🔍 Modo dry-run: dados não foram salvos no banco")
            
        except FileNotFoundError:
            self.stdout.write(
                self.style.ERROR(f"❌ Arquivo não encontrado: {json_file}")
            )
            sys.exit(1)
        except json.JSONDecodeError as e:
            self.stdout.write(
                self.style.ERROR(f"❌ Erro ao decodificar JSON: {e}")
            )
            sys.exit(1)
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"❌ Erro ao processar: {e}")
            )
            sys.exit(1)
    
    def _fix_malformed_json(self, content):
        """Corrige JSONs malformados comuns nos arquivos DMOS"""
        import re
        
        # Remove cabeçalho se presente
        if '=== Saída do comando:' in content:
            lines = content.split('\n')
            json_start = -1
            for i, line in enumerate(lines):
                if line.strip().startswith('{'):
                    json_start = i
                    break
            if json_start >= 0:
                content = '\n'.join(lines[json_start:])
        
        # Aplica correções linha por linha para ser mais preciso
        lines = content.split('\n')
        fixed_lines = []
        
        for i, line in enumerate(lines):
            # Verifica se a linha atual termina com } e a próxima começa com "
            if (line.strip().endswith('}') and 
                i + 1 < len(lines) and 
                lines[i + 1].strip().startswith('"') and
                not line.strip().endswith('},') and
                not line.strip().endswith('},')):
                # Adiciona vírgula se não houver
                fixed_lines.append(line.rstrip() + ',')
            else:
                fixed_lines.append(line)
        
        fixed_content = '\n'.join(fixed_lines)
        
        # Remove vírgulas extras antes de fechamento de objetos/arrays
        fixed_content = re.sub(r',(\s*[}\]])', r'\1', fixed_content)
        
        # Corrige arrays com elementos null incorretos
        fixed_content = re.sub(r'\[null\]', '[null]', fixed_content)
        
        return fixed_content