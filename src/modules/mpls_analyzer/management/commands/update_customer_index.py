"""
Comando Django para atualizar o índice de clientes a partir dos JSONs DMOS
"""
import os
import time
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from modules.mpls_analyzer.customer_parser import CustomerIndexUpdater
from modules.mpls_analyzer.models import CustomerIndex


class Command(BaseCommand):
    help = 'Atualiza o índice de clientes a partir dos JSONs DMOS'

    def add_arguments(self, parser):
        parser.add_argument(
            '--directory',
            type=str,
            help='Diretório com os arquivos JSON (padrão: update/backup_2025-08-24/)'
        )
        parser.add_argument(
            '--rebuild',
            action='store_true',
            help='Reconstroi completamente o índice (limpa dados existentes)'
        )
        parser.add_argument(
            '--file',
            type=str,
            help='Processa apenas um arquivo específico'
        )
        parser.add_argument(
            '--stats',
            action='store_true',
            help='Mostra apenas estatísticas do índice atual'
        )

    def handle(self, *args, **options):
        start_time = time.time()
        
        if options['stats']:
            self.show_stats()
            return
        
        # Define diretório padrão
        default_dir = os.path.join(
            settings.BASE_DIR,
            'modules', 'mpls_analyzer', 'update', 'backup_2025-08-24'
        )
        json_directory = options['directory'] or default_dir
        
        if not os.path.exists(json_directory):
            raise CommandError(f'Diretório não encontrado: {json_directory}')
        
        self.stdout.write(f'Processando JSONs de: {json_directory}')
        
        updater = CustomerIndexUpdater()
        
        try:
            if options['file']:
                # Processa apenas um arquivo
                self.process_single_file(updater, json_directory, options['file'])
            elif options['rebuild']:
                # Reconstrói índice completo
                self.rebuild_index(updater, json_directory)
            else:
                # Atualização incremental
                self.incremental_update(updater, json_directory)
                
        except Exception as e:
            raise CommandError(f'Erro durante processamento: {e}')
        
        elapsed = time.time() - start_time
        self.stdout.write(
            self.style.SUCCESS(
                f'✅ Processamento concluído em {elapsed:.2f} segundos'
            )
        )
        
        # Mostra estatísticas finais
        self.show_stats()
    
    def process_single_file(self, updater, directory, filename):
        """Processa um único arquivo JSON"""
        file_path = os.path.join(directory, filename)
        
        if not os.path.exists(file_path):
            raise CommandError(f'Arquivo não encontrado: {file_path}')
        
        if not filename.endswith('.json'):
            raise CommandError(f'Arquivo deve ter extensão .json: {filename}')
        
        equipment_name = filename.replace('.json', '')
        
        self.stdout.write(f'📁 Processando arquivo: {filename}')
        
        clients_count = updater.update_from_json_file(file_path, equipment_name)
        
        self.stdout.write(
            self.style.SUCCESS(f'✅ {clients_count} clientes processados de {filename}')
        )
    
    def rebuild_index(self, updater, directory):
        """Reconstrói completamente o índice"""
        self.stdout.write(
            self.style.WARNING('🔄 RECONSTRUINDO índice completo (dados existentes serão perdidos)...')
        )
        
        # Confirmação de segurança
        confirm = input('Tem certeza? Digite "sim" para confirmar: ')
        if confirm.lower() != 'sim':
            self.stdout.write('❌ Operação cancelada')
            return
        
        stats = updater.rebuild_full_index(directory)
        
        self.stdout.write('📊 Estatísticas da reconstrução:')
        self.stdout.write(f'   • Arquivos processados: {stats["files_processed"]}')
        self.stdout.write(f'   • Arquivos com erro: {stats["files_failed"]}')
        self.stdout.write(f'   • Clientes únicos encontrados: {stats["clients_found"]}')
        self.stdout.write(f'   • Total de ocorrências: {stats["total_occurrences"]}')
    
    def incremental_update(self, updater, directory):
        """Atualização incremental do índice"""
        self.stdout.write('🔄 Atualizando índice (incremental)...')
        
        json_files = [f for f in os.listdir(directory) if f.endswith('.json')]
        
        if not json_files:
            self.stdout.write(
                self.style.WARNING(f'❌ Nenhum arquivo JSON encontrado em {directory}')
            )
            return
        
        self.stdout.write(f'📁 Encontrados {len(json_files)} arquivos JSON')
        
        stats = {
            'files_processed': 0,
            'files_failed': 0,
            'clients_updated': 0
        }
        
        for filename in sorted(json_files):
            file_path = os.path.join(directory, filename)
            equipment_name = filename.replace('.json', '')
            
            try:
                self.stdout.write(f'   📄 Processando: {filename}', ending='')
                
                clients_count = updater.update_from_json_file(file_path, equipment_name)
                
                self.stdout.write(f' → {clients_count} clientes')
                
                stats['files_processed'] += 1
                stats['clients_updated'] += clients_count
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f' → ERRO: {e}')
                )
                stats['files_failed'] += 1
        
        self.stdout.write('📊 Estatísticas da atualização:')
        self.stdout.write(f'   • Arquivos processados: {stats["files_processed"]}')
        self.stdout.write(f'   • Arquivos com erro: {stats["files_failed"]}')
        self.stdout.write(f'   • Clientes atualizados: {stats["clients_updated"]}')
    
    def show_stats(self):
        """Mostra estatísticas do índice atual"""
        self.stdout.write('📊 ESTATÍSTICAS DO ÍNDICE DE CLIENTES:')
        
        total_clients = CustomerIndex.objects.count()
        
        if total_clients == 0:
            self.stdout.write('   ❌ Índice vazio - execute com --rebuild para construir')
            return
        
        from django.db.models import Sum, Max, Min, Avg
        
        # Calculações simples para evitar conflitos de agregação
        all_customers = CustomerIndex.objects.all()
        total_occurrences = sum(c.total_occurrences for c in all_customers)
        occurrences_list = [c.total_occurrences for c in all_customers if c.total_occurrences > 0]
        
        aggregates = {
            'total_occurrences': total_occurrences,
            'max_occurrences': max(occurrences_list) if occurrences_list else 0,
            'min_occurrences': min(occurrences_list) if occurrences_list else 0,
            'avg_occurrences': sum(occurrences_list) / len(occurrences_list) if occurrences_list else 0,
            'last_update': CustomerIndex.objects.aggregate(last=Max('last_updated'))['last']
        }
        
        self.stdout.write(f'   • Total de clientes únicos: {total_clients}')
        self.stdout.write(f'   • Total de ocorrências: {aggregates["total_occurrences"] or 0}')
        self.stdout.write(f'   • Máximo de ocorrências: {aggregates["max_occurrences"] or 0}')
        self.stdout.write(f'   • Mínimo de ocorrências: {aggregates["min_occurrences"] or 0}')
        avg_value = aggregates["avg_occurrences"] or 0
        self.stdout.write(f'   • Média de ocorrências: {avg_value:.1f}')
        self.stdout.write(f'   • Última atualização: {aggregates["last_update"] or "N/A"}')
        
        # Top 10 clientes
        self.stdout.write('')
        self.stdout.write('🏆 TOP 10 CLIENTES (mais ocorrências):')
        
        top_clients = CustomerIndex.objects.order_by('-total_occurrences')[:10]
        
        for i, client in enumerate(top_clients, 1):
            equipments = len(client.equipment_names) if client.equipment_names else 0
            vpns = len(client.vpn_ids) if client.vpn_ids else 0
            
            self.stdout.write(
                f'   {i:2d}. {client.customer_name[:40]:<40} '
                f'({client.total_occurrences:3d} ocorrências, '
                f'{equipments} equipamentos, {vpns} VPNs)'
            )