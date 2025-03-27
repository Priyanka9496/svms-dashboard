from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import VulnerabilityViewSet, ScanViewSet, dashboard, robots_txt, sitemap_xml, zap_progress_status
from .views import index, list_users, assign_user_to_vulnerability
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import requests

@csrf_exempt
def zap_status_proxy(request):
    scan_id = request.GET.get("scanId")
    zap_url = f"http://127.0.0.1:8080/JSON/ascan/view/status/?scanId={scan_id}"
    response = requests.get(zap_url)
    return JsonResponse(response.json())

router = DefaultRouter()
router.register(r'vulnerabilities', VulnerabilityViewSet, basename='vulnerability')
router.register(r'scans', ScanViewSet, basename='scan')

urlpatterns = [
    path('api/', include(router.urls)),  # Ensure API URLs are under /api/
    path("start_scan/", ScanViewSet.as_view({'post': 'start_scan'}), name="start_scan"),
    path('dashboard/', dashboard, name='dashboard'),
    path('robots.txt', robots_txt, name='robots_txt'),
    path('sitemap.xml', sitemap_xml, name='sitemap_xml'),
    path("zap/ascan/status/", zap_status_proxy),
    path("zap/scan_status/", zap_progress_status, name='zap_progress_status'),
    path("api/users/", list_users, name="list_users"),
    path("api/vulnerabilities/<int:vuln_id>/assign_user/", assign_user_to_vulnerability, name="assign_user"),
]
