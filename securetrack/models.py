from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('DEV', 'Developer'),
        ('QA', 'Quality Analyst'),
        ('PM', 'Project Manager'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='DEV')
    is_approved = models.BooleanField(default=False)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)

    def __str__(self):
        return f'{self.user.username} - {self.role}'



ISSUE_STATUS_CHOICES = [
    ("NEW", "New"),
    ("ASSIGNED", "Assigned"),
    ("IN_PROGRESS", "In Progress"),
    ("QA_REVIEW", "QA Review"),
    ("RESOLVED", "Resolved"),
    ("CLOSED", "Closed"),
]

PRIORITY_CHOICES = [
    ("LOW", "Low"),
    ("MEDIUM", "Medium"),
    ("HIGH", "High"),
    ("CRITICAL", "Critical"),
]

ROLE_CHOICES = [
    ("DEV", "Developer"),
    ("QA", "Quality Analyst"),
    ("PM", "Project Manager"),
]


class WorkflowStage(models.Model):
    name = models.CharField(max_length=50)
    order = models.IntegerField()

    def __str__(self):
        return self.name


class Bug(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    reported_by = models.ForeignKey(User, related_name='reported_bugs', on_delete=models.CASCADE)
    assigned_to = models.ForeignKey(User, related_name='assigned_bugs', null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, choices=ISSUE_STATUS_CHOICES, default="NEW")
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default="MEDIUM")
    module = models.CharField(max_length=100, blank=True)
    reproducible = models.BooleanField(default=True)

    def __str__(self):
        return self.title


class Comment(models.Model):
    bug = models.ForeignKey(Bug, related_name='comments', on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.user.username} on {self.bug.title}"


class AuditLog(models.Model):
    bug = models.ForeignKey(Bug, related_name='audit_logs', on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action} by {self.user.username} at {self.timestamp}"
