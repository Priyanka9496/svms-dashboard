import requests
import time
import pytz
import logging
import json
from rest_framework import viewsets, status
from rest_framework.response import Response
from django.shortcuts import render
from rest_framework.decorators import action
from django.utils.timezone import now
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator
from django_filters.rest_framework import DjangoFilterBackend
from .models import Scan, Vulnerability
from .serializers import ScanSerializer, VulnerabilitySerializer
from django.db.models import Count
from rest_framework.pagination import PageNumberPagination
from .tasks import fetch_zap_results_task
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.http import JsonResponse

# ZAP Configuration
ZAP_BASE_URL = settings.ZAP_BASE_URL
API_KEY = settings.ZAP_API_KEY
TARGET_URL = settings.ZAP_TARGET_URL

NYC_TZ = pytz.timezone("America/New_York")
# Logger Setup
logger = logging.getLogger("django")


def index(request):
    """Simple index page."""
    return render(request, "svms/index.html")


class CustomPagination(PageNumberPagination):
    page_size = 10  # Number of vulnerabilities per page
    page_size_query_param = 'page_size'
    max_page_size = 100  # Prevent huge API responses


class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer

    def run_zap_spider(self):
        """Run ZAP spider to crawl the URL before scanning."""
        spider_url = f"{ZAP_BASE_URL}/JSON/spider/action/scan/?apikey={API_KEY}&url={TARGET_URL}"
        print("zap scan started!")
        response = requests.get(spider_url)
        print(response.status_code)
        if response.status_code == 200:
            return response.json().get("scan")
        return None

    @action(detail=False, methods=['post'])
    def start_scan(self, request):
        # Step 1: Create Scan Record
        print("start_scan endpoint HIT")
        scan = Scan.objects.create(scan_type="SQLI", status="Running")
        print(f"📌 New scan created: ID={scan.id}")

        # Step 2: Run Spider First
        spider_id = self.run_zap_spider()
        if not spider_id:
            scan.status = "Failed"
            scan.result = "Failed to start spider."
            scan.save()
            print('Spidering failed!')
            return JsonResponse({"error": "Spidering failed!"}, status=500)

        # Step 3: Wait for Spider to Complete
        time.sleep(2)  # Give some time for crawling

        # Step 4: Run Active Scan
        zap_scan_url = f"{ZAP_BASE_URL}/JSON/ascan/action/scan/?apikey={API_KEY}&url={TARGET_URL}"
        response = requests.get(zap_scan_url)

        if response.status_code != 200:
            scan.status = "Failed"
            scan.result = response.text
            scan.save()
            return JsonResponse({"error": "Failed to start scan", "details": response.text}, status=500)

        zap_scan_id = response.json().get("scan")
        if not zap_scan_id:
            scan.status = "Failed"
            scan.result = "No scan ID returned by ZAP"
            scan.save()
            return JsonResponse({"error": "Scan ID not received from ZAP"}, status=500)

        print("📤 Sending scan ID to Celery:", scan.id)
        fetch_zap_results_task.delay(scan.id)

        return JsonResponse({
            "message": "Scan started!",
            "scan_id": scan.id,
            "zap_scan_id": zap_scan_id,
            "status": scan.status
        })


def dashboard(request):
    """Basic Dashboard View"""
    total_scans = Scan.objects.count()
    running_scans = Scan.objects.filter(status="Running").count()

    SEVERITY_LEVELS = ['Critical', 'High', 'Medium', 'Low', 'Informational']

    # Default all severities to 0
    severity_counts = {level: 0 for level in SEVERITY_LEVELS}

    # Fetch vulnerabilities grouped by severity
    actual_counts = Vulnerability.objects.values("severity").annotate(count=Count("severity"))
    for entry in actual_counts:
        severity_counts[entry["severity"]] = entry["count"]

    vulnerabilities = Vulnerability.objects.all().order_by("-detected_at")[:5]  # Show latest 5

    context = {
        "total_scans": total_scans,
        "running_scans": running_scans,
        "severity_counts": severity_counts,  # Ensure dictionary always has values
        "severity_levels": SEVERITY_LEVELS,  # Pass severity levels to loop in template
        "vulnerabilities": vulnerabilities,
    }
    return render(request, "svms/dashboard.html", context)


class VulnerabilityViewSet(viewsets.ModelViewSet):
    """Basic API to List Vulnerabilities"""
    queryset = Vulnerability.objects.all().order_by('-detected_at')
    serializer_class = VulnerabilitySerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['severity']
    pagination_class = CustomPagination

    def list(self, request, *args, **kwargs):
        """Paginate and return vulnerabilities"""
        severity = request.GET.get('severity', None)
        queryset = self.get_queryset()

        if severity and severity != "All":
            queryset = queryset.filter(severity=severity)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response({"count": queryset.count(), "vulnerabilities": serializer.data})


def robots_txt(request):
    """Serve robots.txt for web crawlers"""
    content = "User-agent: *\nDisallow: /admin/\n"
    return HttpResponse(content, content_type="text/plain")


def sitemap_xml(request):
    """Serve a basic sitemap.xml"""
    content = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url>
            <loc>http://127.0.0.1:8000/</loc>
            <priority>1.0</priority>
        </url>
        <url>
            <loc>http://127.0.0.1:8000/dashboard/</loc>
            <priority>0.8</priority>
        </url>
    </urlset>
    """
    return HttpResponse(content, content_type="application/xml")


@csrf_exempt
def zap_progress_status(request):
    scan_id = request.GET.get("scanId")
    if not scan_id:
        return JsonResponse({"error": "Missing scanId"}, status=400)

    zap_url = f"http://127.0.0.1:8080/JSON/ascan/view/status/?scanId={scan_id}"

    try:
        zap_response = requests.get(zap_url)
        return JsonResponse(zap_response.json())
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


def list_users(request):
    users = User.objects.values("id", "username")
    return JsonResponse(list(users), safe=False)


@csrf_exempt
def assign_user_to_vulnerability(request, vuln_id):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get("user_id")
            user = User.objects.get(id=user_id)
            vuln = Vulnerability.objects.get(id=vuln_id)
            vuln.assigned_to = user
            vuln.save()
            return JsonResponse({"status": "success", "assigned_to": user.username})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Invalid request"}, status=405)