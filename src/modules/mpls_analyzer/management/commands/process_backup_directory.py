from django.core.management.base import BaseCommand
from django.utils import timezone
from mpls_analyzer.parsers import MplsConfigParser
import os
import json
from datetime import datetime


class Command(BaseCommand):
    help = 'Processa todos os arquivos de backup de um diretório'

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
        
        # Lista todos os arquivos .txt no diretório
        txt_files = [f for f in os.listdir(backup_dir) if f.endswith('.txt')]
        total_files = len(txt_files)
        
        self.stdout.write(f"📁 Processando diretório: {backup_dir}")
        self.stdout.write(f"📄 Arquivos encontrados: {total_files}")
        
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
        
        for filename in sorted(txt_files):
            file_path = os.path.join(backup_dir, filename)
            equipment_name = filename.replace('.txt', '')
            
            try:
                # Verifica se já existe configuração para este equipamento nesta data
                if not force:
                    from mpls_analyzer.models import Equipment, MplsConfiguration
                    try:
                        equipment = Equipment.objects.get(name=equipment_name)
                        existing_config = MplsConfiguration.objects.filter(
                            equipment=equipment,
                            backup_date__date=backup_date.date()
                        ).exists()
                        
                        if existing_config:
                            self.stdout.write(f"⏭️  {equipment_name}: Já processado (use --force para substituir)")
                            skipped += 1
                            continue
                    except Equipment.DoesNotExist:
                        pass
                
                self.stdout.write(f"🔄 Processando: {equipment_name}")
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Auto-detecção: JSON DMOS x CLI
                stripped = content.strip()
                if stripped.startswith('{') or '=== Saída do comando:' in content:
                    # Se tem cabeçalho do comando, remove
                    if '=== Saída do comando:' in content:
                        lines = content.split('\n')
                        json_start = -1
                        for i, line in enumerate(lines):
                            if line.strip().startswith('{'):
                                json_start = i
                                break
                        if json_start >= 0:
                            content = '\n'.join(lines[json_start:])
                    
                    # Corrige JSONs malformados (vírgulas faltando)
                    content = self._fix_malformed_json(content)
                    
                    # Processa como JSON DMOS
                    parsed_data = parser.parse_device_json_text(content)
                else:
                    # Processa como CLI tradicional
                    parsed_data = parser.parse_config_file(file_path)
                
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
                error_msg = f"❌ Erro em {filename}: {str(e)}"
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
    
    def _fix_malformed_json(self, content):
        """Corrige JSONs malformados comuns nos arquivos DMOS"""
        import re
        
        # Padrão para encontrar blocos que terminam com } seguido de " (início de próximo bloco)
        # sem vírgula entre eles
        pattern = r'(\s*})\s*(\n\s*"[^"]+":)'
        
        # Substitui por } seguido de vírgula e depois o próximo bloco
        fixed_content = re.sub(pattern, r'\1,\2', content)
        
        # Corrige outros problemas comuns
        # Remove vírgulas extras antes de fechamento de objetos/arrays
        fixed_content = re.sub(r',(\s*[}\]])', r'\1', fixed_content)
        
        return fixed_content