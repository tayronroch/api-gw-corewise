from django.conf import settings
from django.db import connections
from django.db.utils import OperationalError
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response


@api_view(["GET"])  # Liveness probe
@permission_classes([AllowAny])
def live(request):
    return Response({
        "status": "ok",
        "service": "corewise",
        "mode": "debug" if getattr(settings, "DEBUG", False) else "prod",
    })


@api_view(["GET"])  # Readiness probe (lightweight)
@permission_classes([AllowAny])
def ready(request):
    # Checagem do banco de dados
    db_status = "unknown"
    try:
        conn = connections["default"]
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        db_status = "ok"
    except OperationalError:
        db_status = "down"
    except Exception:
        db_status = "error"

    overall = "ready" if db_status == "ok" else "degraded"

    return Response({
        "status": overall,
        "dependencies": {
            "database": db_status,
        },
    })
