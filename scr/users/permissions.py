# -*- coding: utf-8 -*-
from rest_framework.permissions import BasePermission
from .models import UserProfile

class IsAdminUser(BasePermission):
    """
    Permissao para administradores
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        try:
            profile = request.user.profile
            return profile.role == 'admin'
        except UserProfile.DoesNotExist:
            return request.user.is_superuser

class IsEditorOrAdmin(BasePermission):
    """
    Permissao para editores e administradores
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        try:
            profile = request.user.profile
            return profile.role in ['admin', 'editor']
        except UserProfile.DoesNotExist:
            return request.user.is_superuser

class IsViewerOrAbove(BasePermission):
    """
    Permissao para visualizadores, editores e administradores
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        try:
            profile = request.user.profile
            return profile.role in ['admin', 'editor', 'viewer']
        except UserProfile.DoesNotExist:
            return request.user.is_superuser

class RoleBasedPermission(BasePermission):
    """
    Permissao baseada em roles com controle granular
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        try:
            profile = request.user.profile
            user_role = profile.role
        except UserProfile.DoesNotExist:
            # Se nao tem perfil, considera superuser como admin
            if request.user.is_superuser:
                user_role = 'admin'
            else:
                return False
        
        # Mapeamento de acoes por role
        role_permissions = {
            'admin': {
                'can_create': True,
                'can_read': True,
                'can_update': True,
                'can_delete': True,
                'can_manage_users': True,
                'can_generate_reports': True,
                'can_view_system_logs': True,
            },
            'editor': {
                'can_create': True,
                'can_read': True,
                'can_update': True,
                'can_delete': False,  # Nao pode deletar
                'can_manage_users': False,
                'can_generate_reports': True,
                'can_view_system_logs': False,
            },
            'viewer': {
                'can_create': False,
                'can_read': True,
                'can_update': False,
                'can_delete': False,
                'can_manage_users': False,
                'can_generate_reports': True,
                'can_view_system_logs': False,
            }
        }
        
        permissions = role_permissions.get(user_role, {})
        
        # Verificar permissoes baseadas no metodo HTTP
        if request.method == 'GET':
            return permissions.get('can_read', False)
        elif request.method == 'POST':
            return permissions.get('can_create', False)
        elif request.method in ['PUT', 'PATCH']:
            return permissions.get('can_update', False)
        elif request.method == 'DELETE':
            return permissions.get('can_delete', False)
        
        return False
    
    def has_object_permission(self, request, view, obj):
        """
        Permissoes a nivel de objeto
        """
        if not request.user or not request.user.is_authenticated:
            return False
        
        try:
            profile = request.user.profile
            user_role = profile.role
        except UserProfile.DoesNotExist:
            if request.user.is_superuser:
                user_role = 'admin'
            else:
                return False
        
        # Admins podem tudo
        if user_role == 'admin':
            return True
        
        # Editores podem ver e editar (mas nao deletar)
        if user_role == 'editor':
            if request.method == 'DELETE':
                return False
            return True
        
        # Viewers so podem visualizar
        if user_role == 'viewer':
            return request.method == 'GET'
        
        return False

class UserManagementPermission(BasePermission):
    """
    Permissoes especificas para gerenciamento de usuarios
    Apenas administradores podem gerenciar usuarios
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        try:
            profile = request.user.profile
            return profile.role == 'admin'
        except UserProfile.DoesNotExist:
            return request.user.is_superuser
    
    def has_object_permission(self, request, view, obj):
        # Verificar se e admin
        if not self.has_permission(request, view):
            return False
        
        # Nao permitir auto-exclusao ou auto-desativacao
        if request.method == 'DELETE' and obj.id == request.user.id:
            return False
        
        if view.action == 'toggle_status' and obj.id == request.user.id:
            return False
        
        return True

class ReportPermission(BasePermission):
    """
    Permissoes para geracao de relatorios
    Todos os roles podem gerar relatorios, mas com niveis diferentes
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        try:
            profile = request.user.profile
            return profile.role in ['admin', 'editor', 'viewer']
        except UserProfile.DoesNotExist:
            return request.user.is_superuser
    
    def get_allowed_report_types(self, user):
        """
        Retorna os tipos de relatorios que o usuario pode gerar
        """
        try:
            profile = user.profile
            role = profile.role
        except UserProfile.DoesNotExist:
            if user.is_superuser:
                role = 'admin'
            else:
                return []
        
        report_permissions = {
            'admin': [
                'network_topology',
                'user_activity',
                'system_logs',
                'performance_metrics',
                'security_audit',
                'device_inventory',
                'connection_status'
            ],
            'editor': [
                'network_topology',
                'performance_metrics',
                'device_inventory',
                'connection_status'
            ],
            'viewer': [
                'network_topology',
                'device_inventory',
                'connection_status'
            ]
        }
        
        return report_permissions.get(role, [])

# Decorador para facilitar o uso
def require_role(required_roles):
    """
    Decorador para verificar roles em views
    """
    def decorator(view_func):
        def wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                from django.http import JsonResponse
                return JsonResponse({'error': 'Authentication required'}, status=401)
            
            try:
                profile = request.user.profile
                user_role = profile.role
            except UserProfile.DoesNotExist:
                if request.user.is_superuser:
                    user_role = 'admin'
                else:
                    from django.http import JsonResponse
                    return JsonResponse({'error': 'User profile not found'}, status=403)
            
            if user_role not in required_roles:
                from django.http import JsonResponse
                return JsonResponse(
                    {
                        'error': 'Insufficient permissions',
                        'required_roles': required_roles,
                        'user_role': user_role
                    }, 
                    status=403
                )
            
            return view_func(request, *args, **kwargs)
        
        return wrapped_view
    return decorator