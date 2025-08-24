from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from django.db import transaction
from django.utils import timezone

from modules.mpls_analyzer.models import Equipment, EquipmentJsonBackup


@dataclass
class ImportStats:
    total: int = 0
    success: int = 0
    skipped: int = 0
    errors: int = 0
    total_size: int = 0
    total_lags: int = 0
    total_interfaces: int = 0
    total_vpns: int = 0


def _process_json_file(json_file_path: Path) -> Dict[str, object]:
    equipment_name = json_file_path.stem

    try:
        with open(json_file_path, "r", encoding="utf-8") as f:
            json_data = json.load(f)

        file_size = os.path.getsize(json_file_path)

        try:
            equipment = Equipment.objects.get(name=equipment_name)
        except Equipment.DoesNotExist:
            return {"status": "skipped", "reason": "equipment_not_found", "equipment": equipment_name}

        existing = EquipmentJsonBackup.objects.filter(equipment=equipment).first()
        if existing:
            existing.delete()

        json_backup = EquipmentJsonBackup.objects.create(
            equipment=equipment,
            backup_date=timezone.now(),
            json_data=json_data,
            file_name=f"{equipment_name}.json",
            file_size=file_size,
        )

        return {
            "status": "success",
            "id": json_backup.id,
            "file_size": file_size,
            "total_lags": json_backup.total_lags,
            "total_interfaces": json_backup.total_interfaces,
            "total_vpns": json_backup.total_vpns,
            "equipment": equipment_name,
        }

    except json.JSONDecodeError as e:
        return {"status": "error", "reason": f"invalid_json: {e}", "equipment": equipment_name}
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "reason": f"exception: {e}", "equipment": equipment_name}


def import_jsons_from_dir(
    json_dir: Path,
    *,
    verbose: bool = True,
    remove_on_success: bool = False,
) -> ImportStats:
    """Importa todos os arquivos JSON de um diretório para o banco.

    Args:
        json_dir: Diretório contendo arquivos .json.
        verbose: Se True, imprime o progresso no stdout.
        remove_on_success: Se True, remove o arquivo JSON após importar com sucesso.

    Returns:
        ImportStats com agregados do processo.
    """

    if not json_dir.exists():
        raise FileNotFoundError(f"Diretório não encontrado: {json_dir}")

    json_files = sorted(json_dir.glob("*.json"))
    stats = ImportStats(total=len(json_files))

    start_time = time.time()

    for i, json_file in enumerate(json_files, 1):
        try:
            with transaction.atomic():
                result = _process_json_file(json_file)

            status = result.get("status")

            if status == "success":
                stats.success += 1
                stats.total_size += int(result["file_size"])  # type: ignore[literal-required]
                stats.total_lags += int(result["total_lags"])  # type: ignore[literal-required]
                stats.total_interfaces += int(result["total_interfaces"])  # type: ignore[literal-required]
                stats.total_vpns += int(result["total_vpns"])  # type: ignore[literal-required]

                if remove_on_success:
                    try:
                        json_file.unlink(missing_ok=True)
                    except Exception:
                        pass

            elif status == "skipped":
                stats.skipped += 1
            else:
                stats.errors += 1

            if verbose and i % 10 == 0:
                elapsed = time.time() - start_time
                avg_time = elapsed / i
                eta = avg_time * (stats.total - i)
                print(
                    f"Progresso: {i}/{stats.total} ({i/stats.total*100:.1f}%) | "
                    f"elapsed={elapsed:.1f}s eta={eta:.1f}s"
                )

        except Exception:
            stats.errors += 1

    return stats

