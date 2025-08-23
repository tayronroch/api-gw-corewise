from django.core.management.base import BaseCommand
from django.utils import timezone
from modules.mpls_analyzer.models import MplsConfiguration, Equipment
from modules.mpls_analyzer.parsers import MplsConfigParser
import json


class Command(BaseCommand):
    help = 'Processa configurações MPLS existentes para extrair VPNs estruturadas'

    def add_arguments(self, parser):
        parser.add_argument(
            '--equipment',
            type=str,
            help='Nome específico do equipamento para processar'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Força reprocessamento mesmo se já existirem dados'
        )

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('🚀 Iniciando processamento de configurações MPLS existentes...')
        )

        # Verifica se já existem dados estruturados
        from modules.mpls_analyzer.models import Vpn, VpwsGroup, CustomerService
        
        existing_vpns = Vpn.objects.count()
        existing_vpws = VpwsGroup.objects.count()
        existing_services = CustomerService.objects.count()
        
        if existing_vpns > 0 and not options['force']:
            self.stdout.write(
                self.style.WARNING(
                    f'⚠️  Já existem {existing_vpns} VPNs no banco. '
                    'Use --force para reprocessar.'
                )
            )
            return

        # Filtra configurações para processar
        configs_to_process = MplsConfiguration.objects.all()
        
        if options['equipment']:
            configs_to_process = configs_to_process.filter(
                equipment__name=options['equipment']
            )
            self.stdout.write(
                f'🎯 Processando apenas equipamento: {options["equipment"]}'
            )

        total_configs = configs_to_process.count()
        self.stdout.write(f'📊 Total de configurações para processar: {total_configs}')

        if total_configs == 0:
            self.stdout.write(
                self.style.ERROR('❌ Nenhuma configuração encontrada para processar')
            )
            return

        # Inicializa parser
        parser = MplsConfigParser()
        
        # Contadores
        processed = 0
        errors = 0
        
        # Processa cada configuração
        for config in configs_to_process:
            try:
                self.stdout.write(f'🔄 Processando: {config.equipment.name}')
                
                # Tenta processar como JSON primeiro
                try:
                    parsed_data = parser.parse_device_json_text(config.raw_config)
                except (json.JSONDecodeError, KeyError, TypeError):
                    # Se falhar como JSON, tenta como texto
                    self.stdout.write(f'  📝 Tentando processar como texto...')
                    # Cria um arquivo temporário para o parse_config_file
                    import tempfile
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as temp_file:
                        temp_file.write(config.raw_config)
                        temp_file_path = temp_file.name
                    
                    try:
                        parsed_data = parser.parse_config_file(temp_file_path)
                    finally:
                        import os
                        os.unlink(temp_file_path)
                
                if parsed_data:
                    # Salva no banco de dados
                    parser.save_to_database(parsed_data, config.backup_date)
                    processed += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'  ✅ {config.equipment.name} processado com sucesso')
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'  ⚠️  {config.equipment.name} - Nenhum dado extraído')
                    )
                    
            except Exception as e:
                errors += 1
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Erro ao processar {config.equipment.name}: {str(e)}')
                )

        # Relatório final
        self.stdout.write('\n' + '='*50)
        self.stdout.write('📋 RELATÓRIO FINAL')
        self.stdout.write('='*50)
        self.stdout.write(f'✅ Configurações processadas: {processed}')
        self.stdout.write(f'❌ Erros: {errors}')
        self.stdout.write(f'📊 Total: {total_configs}')
        
        # Conta dados estruturados criados
        new_vpns = Vpn.objects.count()
        new_vpws = VpwsGroup.objects.count()
        new_services = CustomerService.objects.count()
        
        self.stdout.write(f'\n🏗️  DADOS ESTRUTURADOS CRIADOS:')
        self.stdout.write(f'  • VPNs: {new_vpns}')
        self.stdout.write(f'  • Grupos VPWS: {new_vpws}')
        self.stdout.write(f'  • Serviços de Cliente: {new_services}')
        
        if new_vpns > 0:
            self.stdout.write(
                self.style.SUCCESS('\n🎉 Processamento concluído com sucesso!')
            )
        else:
            self.stdout.write(
                self.style.WARNING('\n⚠️  Nenhuma VPN foi extraída. Verifique os logs acima.')
            )
