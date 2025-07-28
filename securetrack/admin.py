from django.contrib import admin
from .models import Comment, AuditLog, WorkflowStage
from svms.models import Vulnerability
from .models import UserProfile


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'role', 'is_approved']
    list_filter = ['is_approved', 'role']
    actions = ['approve_profiles']

    def approve_profiles(self, request, queryset):
        queryset.update(is_approved=True)


admin.site.register(Vulnerability)
admin.site.register(Comment)
admin.site.register(AuditLog)
admin.site.register(WorkflowStage)

