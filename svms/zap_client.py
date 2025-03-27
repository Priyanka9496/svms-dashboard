# svms/zap_client.py
import requests
from django.utils.timezone import now
from .models import Vulnerability


def fetch_zap_results(scan, zap_url, target_url, api_key):
    alerts_url = f"{zap_url}/JSON/core/view/alerts/?apikey={api_key}&baseurl={target_url}"
    response = requests.get(alerts_url)

    if response.status_code != 200:
        print("❌ Failed to fetch alerts from ZAP:", response.text)
        return

    alerts = response.json().get("alerts", [])
    print("🔍 Raw ZAP Alerts Response:", response.json())

    for alert in alerts:
        print(f"✅ Found Vulnerability: {alert['alert']} - {alert['risk']}")
        Vulnerability.objects.create(
            name=alert["alert"],
            description=alert.get("description", ""),
            severity=alert["risk"],
            detected_at=now(),
            scan=scan
        )

    scan.status = "Completed"
    scan.result = f"Found {len(alerts)} vulnerabilities"
    scan.completed_at = now()
    scan.save()
