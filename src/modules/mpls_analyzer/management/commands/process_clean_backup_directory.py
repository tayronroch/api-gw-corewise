from django.core.management.base import BaseCommand
from django.utils import timezone
from mpls_analyzer.parsers import MplsConfigParser
import os
import json
from datetime import datetime


class Command(BaseCommand):
    help = 'Processa diretório de backup com arquivos JSON limpos (formato novo do easy-bkp.py)'

    def add_arguments(self, parser):
        parser.add_argument(
            'backup_dir',
            type=str,
            help='Caminho para o diretório de backup'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Executa sem salvar no banco (apenas mostra o que seria processado)',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Força o processamento mesmo se já existir configuração para o equipamento',
        )

    def handle(self, *args, **options):
        backup_dir = options['backup_dir']
        dry_run = options.get('dry_run', False)
        force = options.get('force', False)
        
        if not os.path.exists(backup_dir):
            self.stdout.write(
                self.style.ERROR(f"❌ Diretório não encontrado: {backup_dir}")
            )
            return
        
        # Procura por arquivos JSON principais (.json) e subdiretórios de dispositivos
        json_files = []
        
        # Método 1: Arquivos .json diretos no diretório (compatibilidade)
        direct_json_files = [f for f in os.listdir(backup_dir) if f.endswith('.json')]
        for filename in direct_json_files:
            file_path = os.path.join(backup_dir, filename)
            device_name = filename.replace('.json', '')
            json_files.append({
                'device_name': device_name,
                'config_file': file_path,
                'method': 'direct'
            })
        
        # Método 2: Subdiretórios com config.json (formato novo)
        for item in os.listdir(backup_dir):
            item_path = os.path.join(backup_dir, item)
            if os.path.isdir(item_path):
                config_file = os.path.join(item_path, 'config.json')
                if os.path.exists(config_file):
                    json_files.append({
                        'device_name': item,
                        'config_file': config_file,
                        'method': 'structured'
                    })
        
        total_files = len(json_files)
        
        self.stdout.write(f"📁 Processando diretório: {backup_dir}")
        self.stdout.write(f"📄 Arquivos JSON encontrados: {total_files}")
        
        if not dry_run:
            self.stdout.write("💾 Modo: SALVAR NO BANCO")
        else:
            self.stdout.write("🔍 Modo: DRY-RUN (não salva)")
        
        if force:
            self.stdout.write("⚠️  Modo: FORCE (substitui configurações existentes)")
        
        # Extrai data do backup do nome do diretório
        backup_date_str = os.path.basename(backup_dir).replace('backup_', '')
        try:
            backup_date = datetime.strptime(backup_date_str, '%Y-%m-%d')
            backup_date = timezone.make_aware(backup_date)
        except ValueError:
            backup_date = timezone.now()
            self.stdout.write(f"⚠️  Não foi possível extrair data do diretório, usando data atual")
        
        self.stdout.write(f"📅 Data do backup: {backup_date.strftime('%d/%m/%Y')}")
        self.stdout.write()
        
        processed_files = 0
        errors = []
        skipped = 0
        parser = MplsConfigParser()
        
        for file_info in sorted(json_files, key=lambda x: x['device_name']):
            device_name = file_info['device_name']
            config_file = file_info['config_file']
            
            try:
                # Verifica se já existe configuração para este equipamento nesta data
                if not force:
                    from mpls_analyzer.models import Equipment, MplsConfiguration
                    try:
                        equipment = Equipment.objects.get(name=device_name)
                        existing_config = MplsConfiguration.objects.filter(
                            equipment=equipment,
                            backup_date__date=backup_date.date()
                        ).exists()
                        
                        if existing_config:
                            self.stdout.write(f"⏭️  {device_name}: Já processado (use --force para substituir)")
                            skipped += 1
                            continue
                    except Equipment.DoesNotExist:
                        pass
                
                self.stdout.write(f"🔄 Processando: {device_name} ({file_info['method']})")
                
                with open(config_file, 'r', encoding='utf-8') as f:
                    json_data = json.load(f)
                
                # Detecta formato do arquivo
                if 'metadata' in json_data and 'data' in json_data:
                    # Formato estruturado (novo easy-bkp.py)
                    config_data = json_data['data']
                    self.stdout.write(f"   📊 Formato: Estruturado (metadados inclusos)")
                    
                    # Verifica metadados
                    metadata = json_data['metadata']
                    if metadata.get('device_name') != device_name:
                        self.stdout.write(f"   ⚠️  Nome do dispositivo divergente: arquivo={device_name}, metadata={metadata.get('device_name')}")
                    
                else:
                    # Formato direto (compatibilidade)
                    config_data = json_data
                    self.stdout.write(f"   📊 Formato: Direto (sem metadados)")
                
                # Processa dados da configuração
                parsed_data = parser.parse_device_json_text(json.dumps(config_data))
                
                # Mostra resumo do que foi extraído
                self.stdout.write(f"   📡 Equipamento: {parsed_data['equipment_name']}")
                if parsed_data.get('equipment_ip'):
                    self.stdout.write(f"   🔗 Loopback: {parsed_data['equipment_ip']}")
                
                # Interfaces de clientes
                customer_interfaces = parsed_data.get('customer_interfaces', [])
                customer_lags = parsed_data.get('customer_lags', [])
                total_customer_interfaces = len(customer_interfaces) + len(customer_lags)
                
                if total_customer_interfaces > 0:
                    self.stdout.write(f"   📡 Interfaces de clientes: {total_customer_interfaces}")
                
                # VPNs
                vpws_groups = parsed_data.get('vpws_groups', [])
                total_vpns = sum(len(group.get('vpns', [])) for group in vpws_groups)
                if total_vpns > 0:
                    self.stdout.write(f"   🆔 VPNs: {total_vpns}")
                
                # Clientes identificados
                customers = parsed_data.get('description_customers', [])
                if customers:
                    self.stdout.write(f"   👥 Clientes: {', '.join(customers[:5])}{'...' if len(customers) > 5 else ''}")
                
                if not dry_run:
                    equipment = parser.save_to_database(parsed_data, backup_date)
                    self.stdout.write(f"   ✅ Salvo: {equipment.name}")
                else:
                    self.stdout.write(f"   🔍 Dry-run: não salvo")
                
                processed_files += 1
                self.stdout.write()
                
            except Exception as e:
                error_msg = f"❌ Erro em {device_name}: {str(e)}"
                errors.append(error_msg)
                self.stdout.write(error_msg)
                self.stdout.write()
        
        # Resumo final
        self.stdout.write("="*50)
        self.stdout.write(f"📊 RESUMO DO PROCESSAMENTO:")
        self.stdout.write(f"   📄 Total de arquivos: {total_files}")
        self.stdout.write(f"   ✅ Processados com sucesso: {processed_files}")
        self.stdout.write(f"   ⏭️  Ignorados (já existem): {skipped}")
        self.stdout.write(f"   ❌ Erros: {len(errors)}")
        
        if errors:
            self.stdout.write(f"\n❌ ERROS ENCONTRADOS:")
            for error in errors:
                self.stdout.write(f"   {error}")
        
        if processed_files > 0:
            self.stdout.write(
                self.style.SUCCESS(f"\n🎉 Processamento concluído! {processed_files} equipamentos atualizados.")
            )
        else:
            self.stdout.write(
                self.style.WARNING(f"\n⚠️  Nenhum arquivo foi processado.")
            )