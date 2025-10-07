import logging
import requests
from django.utils.timezone import now
from django.core.cache import cache
from django.http import HttpResponseForbidden
from ipware import get_client_ip
from .models import RequestLog, BlockedIP

logger = logging.getLogger(__name__)

class IPTrackingMiddleware:
    """
    Middleware for:
    - Logging IP, path, and timestamp (Task 0)
    - Blocking blacklisted IPs (Task 1)
    - Adding geolocation info (Task 2)
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Extract the client IP using django-ipware
        ip, _ = get_client_ip(request)
        path = request.path

        if ip:
            # --- Task 1: Block if IP is blacklisted ---
            if BlockedIP.objects.filter(ip_address=ip).exists():
                logger.warning(f"Blocked request from blacklisted IP: {ip}")
                return HttpResponseForbidden("Your IP has been blocked.")

            # --- Task 2: Get or cache geolocation info ---
            geo_data = cache.get(ip)
            if not geo_data:
                try:
                    response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
                    if response.status_code == 200:
                        data = response.json()
                        geo_data = {
                            "country": data.get("country", ""),
                            "city": data.get("city", ""),
                        }
                        # Cache result for 24 hours
                        cache.set(ip, geo_data, 60 * 60 * 24)
                    else:
                        geo_data = {"country": "", "city": ""}
                except Exception as e:
                    logger.error(f"Geolocation lookup failed for {ip}: {e}")
                    geo_data = {"country": "", "city": ""}
            else:
                logger.debug(f"Used cached geolocation for {ip}")

            # --- Task 0: Log request ---
            RequestLog.objects.create(
                ip_address=ip,
                path=path,
                timestamp=now(),
                country=geo_data.get("country", ""),
                city=geo_data.get("city", ""),
            )

            logger.info(f"Logged {ip} request to {path} [{geo_data.get('country', '')}, {geo_data.get('city', '')}]")

        # Proceed with the request
        return self.get_response(request)
