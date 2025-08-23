"""
Signals para o sistema global de auditoria
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .audit_models import UserActivitySummary, GlobalAuditLog

@receiver(post_save, sender=User)
def create_user_activity_summary(sender, instance, created, **kwargs):
    """Criar resumo de atividade quando usuário for criado"""
    if created:
        UserActivitySummary.objects.create(user=instance)

@receiver(post_save, sender=GlobalAuditLog)
def update_user_activity_summary(sender, instance, created, **kwargs):
    """Atualizar resumo de atividade quando novo log for criado"""
    if created:
        summary, created_summary = UserActivitySummary.objects.get_or_create(user=instance.user)
        # Atualizar contadores pode ser pesado, então fazer periodicamente
        # summary.update_counters()