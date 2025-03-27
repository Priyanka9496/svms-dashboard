from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now


class Vulnerability(models.Model):
    VULN_TYPES = [
        ('SQLI', 'SQL Injection'),
        ('AUTH', 'Broken Authentication'),
        ('XSS', 'Cross-Site Scripting'),
        ('CSRF', 'Cross-Site Request Forgery'),
    ]

    severity_levels = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
        ('General', 'General')
    ]

    name = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=30, choices=severity_levels, default='Low')
    vuln_type = models.CharField(max_length=50, choices=VULN_TYPES, default='SQLI')
    detected_at = models.DateTimeField(auto_now_add=True)
    assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_vulnerabilities')
    scan = models.ForeignKey('Scan', on_delete=models.CASCADE, related_name='vulnerabilities', null=True, blank=True)

    class Meta:
        ordering = ['-detected_at']

    def __str__(self):
        return f"{self.name} ({self.vuln_type}) - {self.severity}"


class Scan(models.Model):
    STATUS_CHOICES = [
        ('Running', 'Running'),
        ('Completed', 'Completed'),
        ('Failed', 'Failed'),
    ]

    SCAN_TYPES = [
        ('SQLI', 'SQL Injection'),
        ('AUTH', 'Authentication'),
        ('XSS', 'Cross-Site Scripting'),
        ('CSRF', 'Cross-Site Request Forgery')
    ]
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Running')
    result = models.TextField(null=True, blank=True)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-started_at']

    def save(self, *args, **kwargs):
        """Automatically updates `completed_at` when scan is marked as completed."""
        if self.status == "Completed" and not self.completed_at:
            self.completed_at = now()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.scan_type} - {self.status}"
