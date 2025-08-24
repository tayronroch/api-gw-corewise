from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from django.conf import settings
from django.utils import timezone

from modules.mpls_analyzer.models import Equipment, BackupProcessLog
from modules.networking.ssh_client import SSHNetworkClient


DEFAULT_DMOS_JSON_COMMAND = "show running-config json"  # ajuste conforme seu ambiente


@dataclass
class CollectResult:
    total: int
    success: int
    errors: int
    output_dir: Path
    errors_list: List[str]


def _collect_single(equipment: Equipment, username: str, password: str, out_dir: Path, json_command: str) -> Tuple[str, bool, str]:
    """Coleta o JSON de um equipamento e salva no diretório out_dir.

    Retorna (equipment_name, success, error_message)
    """
    target_file = out_dir / f"{equipment.name}.json"
    try:
        with SSHNetworkClient(equipment.ip_address, username, password, timeout=30) as client:
            output = client.execute_single_command(json_command, timeout=90)

        # Tenta validar JSON (muitos equipamentos retornam com raiz {"data": {...}})
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError:
            # salva bruto mesmo assim; a etapa de import vai reportar inválidos
            parsed = None

        # Salva em arquivo
        out_dir.mkdir(parents=True, exist_ok=True)
        with open(target_file, "w", encoding="utf-8") as f:
            if parsed is not None:
                json.dump(parsed, f, ensure_ascii=False)
            else:
                f.write(output)

        return equipment.name, True, ""

    except Exception as e:  # noqa: BLE001
        return equipment.name, False, str(e)


def collect_jsons_from_network(
    *,
    username: str,
    password: str,
    output_dir: Path | None = None,
    json_command: str | None = None,
    max_workers: int = 8,
    log_obj: BackupProcessLog | None = None,
) -> CollectResult:
    """Conecta em todos os equipamentos e coleta JSON de configuração.

    Salva os arquivos em modules/mpls_analyzer/update/ por padrão.
    Atualiza BackupProcessLog (se fornecido) com progresso.
    """
    if output_dir is None:
        output_dir = Path(settings.BASE_DIR) / "modules" / "mpls_analyzer" / "update"
    if json_command is None:
        json_command = getattr(settings, "DMOS_JSON_COMMAND", DEFAULT_DMOS_JSON_COMMAND)

    equipments = list(Equipment.objects.all().only("id", "name", "ip_address"))
    total = len(equipments)

    if log_obj is not None:
        log_obj.total_files = total
        log_obj.processed_files = 0
        log_obj.status = "running"
        log_obj.started_at = timezone.now()
        log_obj.errors = ""
        log_obj.save()

    success = 0
    errors = 0
    errors_list: List[str] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_collect_single, eq, username, password, output_dir, json_command)
            for eq in equipments
        ]
        for fut in as_completed(futures):
            name, ok, err = fut.result()
            if ok:
                success += 1
            else:
                errors += 1
                errors_list.append(f"{name}: {err}")
            if log_obj is not None:
                log_obj.processed_files = success + errors
                log_obj.errors = "\n".join(errors_list[:50])  # limita tamanho
                log_obj.save(update_fields=["processed_files", "errors"])

    return CollectResult(total=total, success=success, errors=errors, output_dir=output_dir, errors_list=errors_list)

