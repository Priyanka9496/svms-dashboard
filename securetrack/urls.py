from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('bugs/', views.BugListView.as_view(), name='bug-list'),
    path('profile/', views.user_profile_view, name='user-profile'),
    path('bugs/<int:pk>/', views.BugDetailView.as_view(), name='bug-detail'),
    path('bugs/<int:pk>/comments/', views.CommentListCreateView.as_view(), name='bug-comments'),
    path('dashboard/', views.dashboard_view, name='securetrack-dashboard'),
    path('export/', views.export_csv, name='export-csv'),
    path('bug/<int:bug_id>/update/', views.update_bug_status, name='update-status'),
    path('assign-bug/<int:bug_id>/', views.assign_bug, name='assign-bug'),
    path('request-profile/', views.request_user_profile, name='request-profile'),
    path('profile/edit/', views.update_user_profile, name='edit-profile'),
    path('audit-log/', views.audit_log_view, name='audit-log'),
    path('export-pdf/', views.export_pdf_view, name='export-pdf'),
    path('schedule-report/', views.schedule_report_view, name='schedule-report'),
    path('login/', auth_views.LoginView.as_view(template_name='securetrack/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),
    path('register/', views.register_view, name='register'),
    path('chatbot/', views.chatbot_reply, name='chatbot-reply'),
]
