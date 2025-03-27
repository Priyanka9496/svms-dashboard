# svms/tasks.py
from celery import shared_task
from django.utils.timezone import now
from django.conf import settings
from .models import Scan, Vulnerability
import requests


@shared_task
def fetch_zap_results_task(scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        print(f"❌ Scan with ID {scan_id} does not exist")
        return

    zap_url = settings.ZAP_BASE_URL
    target_url = settings.ZAP_TARGET_URL
    api_key = settings.ZAP_API_KEY

    alerts_url = f"{zap_url}/JSON/core/view/alerts/?apikey={api_key}&baseurl={target_url}"
    response = requests.get(alerts_url)

    if response.status_code != 200:
        print("❌ Failed to fetch alerts from ZAP:", response.text)
        scan.status = "Failed"
        scan.result = "Error fetching from ZAP"
        scan.completed_at = now()
        scan.save()
        return

    alerts = response.json().get("alerts", [])
    print(f"📦 Received {len(alerts)} alerts from ZAP")

    for alert in alerts:
        print(f"✅ Storing: {alert['alert']} - {alert['risk']}")
        Vulnerability.objects.create(
            name=alert["alert"],
            description=alert.get("description", ""),
            severity=alert["risk"],
            detected_at=now(),
            scan=scan
        )

    # ✅ Mark scan as completed AFTER vulnerabilities are inserted
    scan.status = "Completed"
    scan.result = f"Found {len(alerts)} vulnerabilities"
    scan.completed_at = now()
    scan.save()

    print(f"✅ Scan {scan.id} marked as Completed with {len(alerts)} vulnerabilities.")
