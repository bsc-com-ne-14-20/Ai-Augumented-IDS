import requests as http

def get_ip_info(ip: str) -> dict:
    """
    Fetch geolocation + VPN/proxy detection from ip-api.com.
    Free tier: 45 req/min, no API key needed.
    Falls back gracefully on failure or private IPs.
    """
    private_prefixes = ("127.", "192.168.", "10.", "172.", "::1", "localhost")
    if any(ip.startswith(p) for p in private_prefixes):
        return {
            "country": "Local", "city": "Local",
            "latitude": None, "longitude": None,
            "isp": "Local Network",
            "is_vpn": False, "is_proxy": False, "is_tor": False,
        }
    try:
        r = http.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,lat,lon,isp,proxy,hosting"},
            timeout=3
        )
        data = r.json()
        if data.get("status") == "success":
            return {
                "country":   data.get("country"),
                "city":      data.get("city"),
                "latitude":  data.get("lat"),
                "longitude": data.get("lon"),
                "isp":       data.get("isp"),
                "is_vpn":    data.get("proxy", False) or data.get("hosting", False),
                "is_proxy":  data.get("proxy", False),
                "is_tor":    False,
            }
    except Exception:
        pass
    return {
        "country": None, "city": None,
        "latitude": None, "longitude": None,
        "isp": None,
        "is_vpn": False, "is_proxy": False, "is_tor": False,
    }