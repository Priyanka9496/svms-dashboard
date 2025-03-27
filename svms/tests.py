from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from .models import Vulnerability, Scan

class VulnerabilityModelTest(TestCase):
    """Test cases for the Vulnerability model"""

    def setUp(self):
        Vulnerability.objects.all().delete()
        self.vuln = Vulnerability.objects.create(
            name="SQL Injection",
            description="Input fields are vulnerable to SQL Injection.",
            severity="Critical",
            vuln_type="SQLI"
        )

    def test_vulnerability_creation(self):
        """Ensure the vulnerability is created correctly"""
        self.assertEqual(self.vuln.name, "SQL Injection")
        self.assertEqual(self.vuln.vuln_type, "SQLI")
        self.assertEqual(self.vuln.severity, "Critical")

    def test_vulnerability_string_representation(self):
        """Check the string representation of the model"""
        self.assertEqual(str(self.vuln), "SQL Injection (SQLI) - Critical")


class ScanModelTest(TestCase):
    """Test cases for the Scan model"""

    def setUp(self):
        Scan.objects.all().delete()
        self.scan = Scan.objects.create(
            scan_type="SQLI",
            status="Pending"
        )

    def test_scan_creation(self):
        """Ensure the scan is created correctly"""
        self.assertEqual(self.scan.scan_type, "SQLI")
        self.assertEqual(self.scan.status, "Pending")

    def test_scan_string_representation(self):
        """Check the string representation of the model"""
        self.assertEqual(str(self.scan), "SQLI - Pending")


class VulnerabilityAPITestCase(APITestCase):
    """API test cases for vulnerabilities"""

    def setUp(self):
        Vulnerability.objects.all().delete()
        self.vuln = Vulnerability.objects.create(
            name="Broken Authentication",
            description="Weak password policy detected.",
            severity="High",
            vuln_type="AUTH"
        )
        self.list_url = reverse('vulnerability-list')  # Uses DefaultRouter endpoint

    def test_list_vulnerabilities(self):
        """Test listing vulnerabilities"""
        response = self.client.get(self.list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)  # Ensure one record exists

    def test_create_vulnerability(self):
        """Test creating a new vulnerability via API"""
        data = {
            "name": "Test SQL Injection",
            "description": "Test vulnerability detection.",
            "severity": "Medium",
            "vuln_type": "SQLI"
        }
        response = self.client.post(self.list_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Vulnerability.objects.count(), 2)  # Ensured two records exist


class ScanAPITestCase(APITestCase):
    """API test cases for scan operations"""

    def setUp(self):
        Scan.objects.all().delete()
        Vulnerability.objects.all().delete()
        self.scan = Scan.objects.create(scan_type="SQLI", status="Pending")
        self.scan_url = reverse('scan-detail', args=[self.scan.id])
        self.run_scan_url = reverse('scan-run-scan', args=[self.scan.id])  # Corrected URL name

    def test_list_scans(self):
        """Test listing scans"""
        response = self.client.get(reverse('scan-list'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_create_scan(self):
        """Test creating a new scan"""
        data = {"scan_type": "AUTH"}
        response = self.client.post(reverse('scan-list'), data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Scan.objects.count(), 2)

    def test_run_scan(self):
        """Test executing a scan"""
        response = self.client.post(self.run_scan_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, "Completed")  # Ensured scan status is updated
        self.assertEqual(Vulnerability.objects.count(), 2)  # Ensured two vulnerability is created
