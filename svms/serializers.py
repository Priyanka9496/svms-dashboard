from rest_framework import serializers
from .models import Vulnerability, Scan


class VulnerabilitySerializer(serializers.ModelSerializer):
    assigned_to = serializers.SerializerMethodField()
    class Meta:
        model = Vulnerability
        fields = '__all__'

    def get_assigned_to(self, obj):
        return obj.assigned_to.username if obj.assigned_to else None

class ScanSerializer(serializers.ModelSerializer):
    vulnerabilities = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = '__all__'

    def get_vulnerabilities(self, obj):
        if obj.completed_at is None:
            return []

        vulnerabilities = Vulnerability.objects.filter(
            detected_at__gte=obj.started_at, detected_at__lte=obj.completed_at
        )

        return VulnerabilitySerializer(vulnerabilities, many=True).data
