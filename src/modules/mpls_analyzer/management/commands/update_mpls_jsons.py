from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from modules.mpls_analyzer.services.import_jsons import import_jsons_from_dir


class Command(BaseCommand):
    help = (
        "Importa arquivos JSON de equipamentos Datacom e atualiza os backups no banco. "
        "Por padrão, lê de modules/mpls_analyzer/update."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--path",
            dest="path",
            type=str,
            default=None,
            help="Diretório contendo os arquivos .json (default: modules/mpls_analyzer/update)",
        )
        parser.add_argument(
            "--remove-on-success",
            dest="remove_on_success",
            action="store_true",
            help="Remove o arquivo JSON após importação bem-sucedida.",
        )

    def handle(self, *args, **options):
        # Diretório padrão: src/modules/mpls_analyzer/update
        default_dir = Path(settings.BASE_DIR) / "modules" / "mpls_analyzer" / "update"
        input_dir = Path(options["path"]) if options.get("path") else default_dir

        try:
            stats = import_jsons_from_dir(input_dir, verbose=True, remove_on_success=options["remove_on_success"])
        except FileNotFoundError as e:
            raise CommandError(str(e))

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("IMPORTAÇÃO CONCLUÍDA"))
        self.stdout.write(
            f"Total: {stats.total} | Sucessos: {stats.success} | "
            f"Pulados: {stats.skipped} | Erros: {stats.errors}"
        )

