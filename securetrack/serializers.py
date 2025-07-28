from rest_framework import serializers
from .models import  Comment, AuditLog
from svms.models import Vulnerability


class BugSerializer(serializers.ModelSerializer):
    assigned_to = serializers.StringRelatedField()

    class Meta:
        model = Vulnerability
        fields = [
            'id',
            'name',
            'description',
            'severity',
            'vuln_type',
            'detected_at',
            'assigned_to',
        ]


class CommentSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Comment
        fields = ['id', 'user', 'message', 'created_at']


class AuditLogSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = AuditLog
        fields = ['id', 'bug', 'action', 'user', 'timestamp']
