from celery import shared_task
from django.utils.timezone import now, timedelta
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ["/admin", "/login"]

@shared_task
def detect_suspicious_ips():
    one_hour_ago = now() - timedelta(hours=1)
    logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    ip_counts = {}
    for log in logs:
        ip_counts.setdefault(log.ip_address, {"count": 0, "paths": []})
        ip_counts[log.ip_address]["count"] += 1
        ip_counts[log.ip_address]["paths"].append(log.path)

    for ip, data in ip_counts.items():
        reason = None
        if data["count"] > 100:
            reason = f"Exceeded 100 requests in the last hour ({data['count']})"
        elif any(path in SENSITIVE_PATHS for path in data["paths"]):
            reason = "Accessed sensitive path"

        if reason:
            SuspiciousIP.objects.create(ip_address=ip, reason=reason)
