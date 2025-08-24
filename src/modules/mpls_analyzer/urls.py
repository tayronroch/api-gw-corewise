from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('setup-mfa/', views.setup_mfa, name='setup_mfa'),
    path('verify-mfa/', views.verify_mfa, name='verify_mfa'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('search/', views.search_view, name='search'),
    path('advanced-search/', views.advanced_search_view, name='advanced_search'),
    path('equipment/<int:equipment_id>/', views.equipment_detail, name='equipment_detail'),
    path('update-database/', views.update_database_view, name='update_database'),
    path('fix-malformed-json/', views.fix_malformed_json, name='fix_malformed_json'),
    path('customer-report/', views.customer_report_view, name='customer_report_view'),
    path('api/search/', views.api_search, name='api_search'),
    path('api/unified-search/', views.unified_search, name='unified_search'),
    path('api/vpn-report/', views.vpn_report, name='vpn_report'),
    path('api/customer-interface-report/', views.customer_interface_report, name='customer_interface_report'),
    path('api/customer-report/', views.customer_report, name='customer_report'),
    path('api/customer-report/excel/', views.customer_report_excel, name='customer_report_excel'),
    path('api/update-status/', views.update_status_api, name='update_status_api'),
    
    # Admin URLs  
    path('admin-panel/', views.admin_panel, name='admin_panel'),
    path('admin/users/', views.admin_users_list, name='admin_users_list'),
    path('admin/users/<int:user_id>/', views.admin_user_detail, name='admin_user_detail'),
    path('admin/users/create/', views.admin_create_user, name='admin_create_user'),
    
    # User Management URLs
    path('users/', views.user_management, name='user_management'),
    path('users/create/', views.create_user, name='create_user'),
    path('users/<int:user_id>/edit/', views.edit_user, name='edit_user'),
    path('users/<int:user_id>/toggle-status/', views.toggle_user_status, name='toggle_user_status'),
    path('users/<int:user_id>/delete/', views.delete_user, name='delete_user'),
    
    # User Profile URLs
    path('profile/', views.user_profile, name='user_profile'),
    path('profile/change-password/', views.change_password, name='change_password'),
    path('profile/setup-mfa/', views.setup_mfa, name='setup_mfa'),
    path('profile/disable-mfa/', views.disable_mfa, name='disable_mfa'),
    path('profile/toggle-mfa/', views.toggle_mfa, name='toggle_mfa'),
    
    # Manager URLs for Access and Audit Logs
    path('manager/audit-dashboard/', views.audit_dashboard, name='audit_dashboard'),
    path('manager/access-logs/', views.access_logs_view, name='access_logs'),
    path('manager/audit-logs/', views.audit_logs_view, name='audit_logs'),
    path('manager/access-logs/export/', views.export_access_logs, name='export_access_logs'),
    path('manager/audit-logs/export/', views.export_audit_logs, name='export_audit_logs'),
    path('manager/security-settings/', views.security_settings_view, name='security_settings'),
]