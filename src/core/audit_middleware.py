"""
Middleware global de auditoria para CoreWise
Captura automaticamente todas as ações dos usuários em tempo real
"""
import time
import json
import traceback
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser
from django.urls import resolve
from django.core.exceptions import PermissionDenied
from django.http import Http404
from .audit_models import GlobalAuditLog, GlobalAccessLog, GlobalLoginAttempt, GlobalSecuritySettings


class GlobalAuditMiddleware(MiddlewareMixin):
    """
    Middleware que captura automaticamente todas as ações dos usuários
    e registra logs de auditoria globais
    """
    
    # Endpoints que devem ser ignorados no log
    IGNORE_PATHS = [
        '/static/',
        '/media/',
        '/favicon.ico',
        '/admin/jsi18n/',
        '/health/',
        '/metrics/',
    ]
    
    # Métodos HTTP que geram logs de auditoria
    AUDIT_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE']
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)

    def process_request(self, request):
        """Preparar dados antes de processar a requisição"""
        request.audit_start_time = time.time()
        request.audit_data = {
            'ip_address': self.get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'endpoint': request.path,
            'method': request.method,
        }
        
        # Verificar bloqueios de segurança se usuário estiver autenticado
        if hasattr(request, 'user') and request.user.is_authenticated:
            self._check_security_blocks(request)
    
    def process_response(self, request, response):
        """Processar resposta e registrar auditoria"""
        # Ignorar caminhos específicos
        if self._should_ignore_path(request.path):
            return response
        
        # Só auditar se usuário estiver autenticado
        if not hasattr(request, 'user') or isinstance(request.user, AnonymousUser):
            return response
            
        # Calcular tempo de execução
        execution_time = None
        if hasattr(request, 'audit_start_time'):
            execution_time = int((time.time() - request.audit_start_time) * 1000)
        
        try:
            # Determinar ação baseada no método HTTP e endpoint
            action, description = self._determine_action(request, response)
            
            if action:
                # Dados básicos da auditoria
                audit_data = {
                    'user': request.user,
                    'action': action,
                    'description': description,
                    'ip_address': request.audit_data['ip_address'],
                    'user_agent': request.audit_data['user_agent'],
                    'endpoint': request.audit_data['endpoint'],
                    'success': 200 <= response.status_code < 400,
                    'execution_time_ms': execution_time,
                    'app_name': self._get_app_name(request),
                    'module_name': self._get_module_name(request),
                }
                
                # Adicionar dados específicos do erro se houver
                if response.status_code >= 400:
                    audit_data['error_message'] = f"HTTP {response.status_code}"
                
                # Adicionar dados específicos baseados na ação
                self._add_action_specific_data(request, response, audit_data)
                
                # Criar log de auditoria
                GlobalAuditLog.objects.create(**audit_data)
                
        except Exception as e:
            # Em caso de erro no middleware, não quebrar a aplicação
            # mas registrar o erro no log de auditoria se possível
            try:
                GlobalAuditLog.objects.create(
                    user=request.user,
                    action='system_error',
                    description=f'Erro no middleware de auditoria: {str(e)}',
                    ip_address=request.audit_data['ip_address'],
                    user_agent=request.audit_data['user_agent'],
                    endpoint=request.audit_data['endpoint'],
                    success=False,
                    error_message=str(e),
                    app_name='core_audit',
                    module_name='middleware'
                )
            except:
                pass  # Se não conseguir nem isso, ignore para não quebrar
        
        return response
    
    def process_exception(self, request, exception):
        """Registrar exceções não tratadas"""
        if (hasattr(request, 'user') and 
            not isinstance(request.user, AnonymousUser) and
            not self._should_ignore_path(request.path)):
            
            try:
                error_message = f"{exception.__class__.__name__}: {str(exception)}"
                
                # Determinar tipo de erro
                if isinstance(exception, PermissionDenied):
                    action = 'access_denied'
                elif isinstance(exception, Http404):
                    action = 'not_found'
                else:
                    action = 'system_error'
                
                GlobalAuditLog.objects.create(
                    user=request.user,
                    action=action,
                    description=f'Exceção não tratada: {error_message}',
                    ip_address=request.audit_data['ip_address'],
                    user_agent=request.audit_data['user_agent'],
                    endpoint=request.audit_data['endpoint'],
                    success=False,
                    error_message=error_message,
                    app_name=self._get_app_name(request),
                    module_name=self._get_module_name(request),
                    additional_data={'traceback': traceback.format_exc()}
                )
            except:
                pass  # Não quebrar a aplicação por erro de logging
        
        return None  # Continue o processamento normal da exceção

    def _should_ignore_path(self, path):
        """Verificar se o caminho deve ser ignorado"""
        return any(ignore_path in path for ignore_path in self.IGNORE_PATHS)
    
    def _check_security_blocks(self, request):
        """Verificar bloqueios de segurança"""
        user = request.user
        ip = request.audit_data['ip_address']
        
        # Verificar se IP está bloqueado
        if GlobalLoginAttempt.is_ip_blocked(ip):
            raise PermissionDenied("IP temporariamente bloqueado por muitas tentativas falhadas.")
        
        # Verificar se usuário está bloqueado
        if GlobalLoginAttempt.is_user_blocked(user.username):
            raise PermissionDenied("Usuário temporariamente bloqueado por muitas tentativas falhadas.")
    
    def _determine_action(self, request, response):
        """Determinar a ação baseada no método HTTP e endpoint"""
        method = request.method
        path = request.path
        
        # Apenas auditar métodos que fazem mudanças ou acessos importantes
        if method not in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
            return None, None
        
        # Determinar ação baseada no endpoint
        if '/api/' in path:
            if 'search' in path:
                return 'search', f'Busca realizada: {path}'
            elif 'export' in path or 'report' in path:
                return 'report_export', f'Relatório exportado: {path}'
            elif 'dashboard' in path:
                return 'dashboard_view', f'Dashboard visualizado: {path}'
            elif method == 'POST':
                return 'create', f'Registro criado via API: {path}'
            elif method in ['PUT', 'PATCH']:
                return 'update', f'Registro atualizado via API: {path}'
            elif method == 'DELETE':
                return 'delete', f'Registro deletado via API: {path}'
            elif method == 'GET' and response.status_code == 200:
                return 'api_access', f'API acessada: {path}'
        
        # Ações específicas do Django Admin
        elif '/admin/' in path:
            if method == 'POST':
                if 'add/' in path:
                    return 'admin_create', f'Registro criado no admin: {path}'
                elif 'change/' in path:
                    return 'admin_update', f'Registro atualizado no admin: {path}'
                elif 'delete/' in path:
                    return 'admin_delete', f'Registro deletado no admin: {path}'
            elif method == 'GET' and response.status_code == 200:
                return 'admin_access', f'Painel admin acessado: {path}'
        
        # Login/Logout
        elif 'login' in path:
            if method == 'POST':
                if response.status_code in [200, 302]:  # Sucesso
                    return 'login', 'Login realizado com sucesso'
                else:
                    return 'login', 'Tentativa de login falhada'
        elif 'logout' in path:
            return 'logout', 'Logout realizado'
        
        # Outras ações importantes
        elif method == 'GET' and response.status_code == 200:
            # Apenas registrar acessos GET importantes (não todos)
            if any(keyword in path for keyword in ['topology', 'mpls', 'engineering', 'security']):
                module = self._get_module_name(request)
                return f'{module}_view', f'Módulo {module} visualizado: {path}'
        
        return None, None
    
    def _get_app_name(self, request):
        """Obter nome da app Django baseado na URL"""
        try:
            resolver_match = resolve(request.path)
            if resolver_match:
                return resolver_match.app_name or resolver_match.namespace or 'unknown'
        except:
            pass
        return 'unknown'
    
    def _get_module_name(self, request):
        """Obter nome do módulo baseado na URL"""
        path = request.path.lower()
        
        if 'mpls' in path:
            return 'MPLS'
        elif 'topology' in path:
            return 'Topology' 
        elif 'engineering' in path:
            return 'Engineering'
        elif 'security' in path:
            return 'Security'
        elif 'networking' in path:
            return 'Networking'
        elif 'users' in path:
            return 'Users'
        elif 'admin' in path:
            return 'Admin'
        
        return ''
    
    def _add_action_specific_data(self, request, response, audit_data):
        """Adicionar dados específicos baseados na ação"""
        # Capturar query parameters para buscas
        if audit_data['action'] in ['search', 'advanced_search']:
            query_params = dict(request.GET)
            if query_params:
                audit_data['search_query'] = json.dumps(query_params)
                audit_data['additional_data'] = {'query_params': query_params}
        
        # Capturar dados de POST para criações/atualizações
        elif audit_data['action'] in ['create', 'update', 'admin_create', 'admin_update']:
            if hasattr(request, 'POST') and request.POST:
                # Filtrar dados sensíveis
                safe_data = {}
                for key, value in request.POST.items():
                    if 'password' not in key.lower() and 'secret' not in key.lower():
                        safe_data[key] = value
                
                if safe_data:
                    audit_data['additional_data'] = {'form_data': safe_data}
    
    @staticmethod
    def get_client_ip(request):
        """Obter IP real do cliente considerando proxies"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecurityMiddleware(MiddlewareMixin):
    """
    Middleware de segurança para implementar rate limiting e outras proteções
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """Verificar limites de taxa antes de processar requisição"""
        if not hasattr(request, 'user') or isinstance(request.user, AnonymousUser):
            return None
            
        # Obter configurações de segurança
        settings = GlobalSecuritySettings.get_settings()
        
        # Verificar rate limiting para APIs
        if '/api/' in request.path:
            if self._check_rate_limit(request.user, 'api', settings.api_rate_limit_per_minute):
                return self._rate_limit_response(request, 'API rate limit exceeded')
        
        # Verificar rate limiting para buscas
        if 'search' in request.path:
            if self._check_rate_limit(request.user, 'search', settings.search_rate_limit_per_minute):
                return self._rate_limit_response(request, 'Search rate limit exceeded')
        
        # Verificar rate limiting para exports
        if 'export' in request.path or 'report' in request.path:
            if self._check_rate_limit(request.user, 'export', settings.export_rate_limit_per_hour, 'hour'):
                return self._rate_limit_response(request, 'Export rate limit exceeded')
        
        return None
    
    def _check_rate_limit(self, user, action_type, limit, period='minute'):
        """Verificar se usuário excedeu limite de taxa"""
        from datetime import timedelta
        from django.utils import timezone
        
        if period == 'hour':
            time_window = timezone.now() - timedelta(hours=1)
        else:  # minute
            time_window = timezone.now() - timedelta(minutes=1)
        
        # Mapear tipos de ação
        action_map = {
            'api': ['create', 'update', 'delete', 'api_access'],
            'search': ['search', 'advanced_search'],
            'export': ['report_export']
        }
        
        actions = action_map.get(action_type, [])
        
        # Contar ações no período
        count = GlobalAuditLog.objects.filter(
            user=user,
            action__in=actions,
            timestamp__gte=time_window
        ).count()
        
        return count >= limit
    
    def _rate_limit_response(self, request, message):
        """Retornar resposta de rate limit e registrar no log"""
        from django.http import JsonResponse
        
        # Registrar tentativa de rate limit
        try:
            GlobalAuditLog.objects.create(
                user=request.user,
                action='rate_limit_exceeded',
                description=message,
                ip_address=GlobalAuditMiddleware.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                endpoint=request.path,
                success=False,
                error_message=message,
                app_name='security',
                module_name='rate_limiting'
            )
        except:
            pass  # Não quebrar por erro de logging
        
        return JsonResponse(
            {'error': message, 'status': 429},
            status=429
        )