#!/usr/bin/env python3
"""
GeoIP enrichment script for AstroSIEM
Extracts IP addresses from parsed logs and fetches geographic coordinates using IP-API
Caches results to avoid rate limiting (45 requests/minute)
"""

import json
import re
import time
from pathlib import Path
import urllib.request
import urllib.error

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
ENGINE_DIR = SCRIPT_DIR.parent

# Define paths
PARSED_LOGS_FILE = ENGINE_DIR / "processed-data" / "events-security-processed.json"
GEOIP_CACHE_FILE = ENGINE_DIR / "processed-data" / "geoip-cache.json"
# Save directly to dashboard directory where the dashboard expects it
GEOIP_ENRICHED_FILE = ENGINE_DIR / "dashboard" / "geoip-map-data.json"


def extract_ips_from_logs(logs):
    """Extract unique IP addresses from log messages."""
    ips = set()
    ip_pattern = re.compile(r"rhost=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")

    for log in logs:
        message = log.get("message", "")
        matches = ip_pattern.findall(message)
        ips.update(matches)

    return list(ips)


def load_geoip_cache():
    """Load cached GeoIP results."""
    if GEOIP_CACHE_FILE.exists():
        try:
            with open(GEOIP_CACHE_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_geoip_cache(cache):
    """Save GeoIP cache to file."""
    with open(GEOIP_CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def fetch_geoip_data(ip, cache):
    """Fetch GeoIP data from IP-API (free, no account required)."""
    # Check cache first
    if ip in cache:
        return cache[ip]

    try:
        # IP-API free endpoint (45 requests/minute allowed)
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query"

        req = urllib.request.Request(
            url, headers={"User-Agent": "AstroSIEM/1.0 (Security Analysis)"}
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())

            if data.get("status") == "success":
                geo_data = {
                    "ip": data.get("query"),
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "XX"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "as": data.get("as"),
                }

                # Update cache
                cache[ip] = geo_data
                return geo_data
            else:
                print(
                    f"  [!] Failed to lookup {ip}: {data.get('message', 'Unknown error')}"
                )
                return None

    except urllib.error.HTTPError as e:
        if e.code == 429:
            print(f"  [!] Rate limit hit for {ip}. Waiting 60 seconds...")
            time.sleep(60)
            return fetch_geoip_data(ip, cache)  # Retry
        else:
            print(f"  [!] HTTP error for {ip}: {e}")
            return None
    except Exception as e:
        print(f"  [!] Error fetching GeoIP for {ip}: {e}")
        return None


def enrich_logs_with_geoip(logs, cache):
    """Add GeoIP data to log entries."""
    ip_pattern = re.compile(r"rhost=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")
    enriched_logs = []

    # Track unique IPs for batch processing
    unique_ips = extract_ips_from_logs(logs)
    total_ips = len(unique_ips)

    print(f"[*] Found {total_ips} unique IP addresses")
    print(f"[*] Fetching GeoIP data (cached: {len(cache)} IPs)")

    # Fetch GeoIP data for new IPs
    new_ips = [ip for ip in unique_ips if ip not in cache]
    for idx, ip in enumerate(new_ips, 1):
        print(f"  [{idx}/{len(new_ips)}] Looking up {ip}...", end=" ")
        geo_data = fetch_geoip_data(ip, cache)
        if geo_data:
            print(f"✓ {geo_data['country']}, {geo_data['city']}")
        else:
            print("✗ Failed")

        # Rate limiting: max 45 requests/minute = 1 request every 1.4 seconds
        if idx < len(new_ips):
            time.sleep(1.5)

    # Enrich logs with GeoIP data
    for log in logs:
        message = log.get("message", "")
        matches = ip_pattern.findall(message)

        if matches:
            ip = matches[0]
            if ip in cache:
                log["source_ip"] = ip
                log["geoip"] = cache[ip]

        enriched_logs.append(log)

    return enriched_logs


def generate_geoip_summary(logs):
    """Generate summary statistics for GeoIP data."""
    country_counts = {}
    city_counts = {}

    for log in logs:
        if "geoip" in log:
            geo = log["geoip"]
            country = geo.get("country", "Unknown")
            city = geo.get("city", "Unknown")

            country_counts[country] = country_counts.get(country, 0) + 1
            city_counts[city] = city_counts.get(city, 0) + 1

    # Sort by count descending
    top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
    top_cities = sorted(city_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_events": len(logs),
        "events_with_geoip": sum(1 for log in logs if "geoip" in log),
        "unique_countries": len(country_counts),
        "unique_cities": len(city_counts),
        "top_countries": [{"country": c, "count": n} for c, n in top_countries],
        "top_cities": [{"city": c, "count": n} for c, n in top_cities],
    }


def main():
    print("=" * 60)
    print("AstroSIEM GeoIP Enrichment")
    print("=" * 60)

    # Load parsed logs
    if not PARSED_LOGS_FILE.exists():
        print(f"[!] Parsed logs not found: {PARSED_LOGS_FILE}")
        print("[!] Run parse-syslog-security.py first")
        return

    with open(PARSED_LOGS_FILE, "r") as f:
        logs = json.load(f)

    print(f"[*] Loaded {len(logs)} log entries")

    # Load cache
    cache = load_geoip_cache()

    # Enrich logs
    enriched_logs = enrich_logs_with_geoip(logs, cache)

    # Save updated cache
    save_geoip_cache(cache)
    print(f"[*] Saved GeoIP cache ({len(cache)} IPs)")

    # Generate summary
    summary = generate_geoip_summary(enriched_logs)

    # Save enriched logs
    with open(GEOIP_ENRICHED_FILE, "w") as f:
        json.dump({"logs": enriched_logs, "summary": summary}, f, indent=2)

    print("\n" + "=" * 60)
    print("GeoIP Enrichment Complete!")
    print("=" * 60)
    print(f"[*] Total events: {summary['total_events']}")
    print(f"[*] Events with GeoIP: {summary['events_with_geoip']}")
    print(f"[*] Unique countries: {summary['unique_countries']}")
    print(f"[*] Unique cities: {summary['unique_cities']}")
    print(f"\n[*] Top attacking countries:")
    for country in summary["top_countries"][:5]:
        print(f"    - {country['country']}: {country['count']} events")
    print(f"\n[*] Output saved to: {GEOIP_ENRICHED_FILE}")


if __name__ == "__main__":
    main()
