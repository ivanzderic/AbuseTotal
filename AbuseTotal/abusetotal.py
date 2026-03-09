import requests
import socket
import csv
import datetime
import time
import os

# ==========================================
# CONFIGURATION - PLACE YOUR KEYS HERE
# ==========================================
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_KEY_HERE"
ABUSEIPDB_API_KEY = "YOUR_VIRUSTOTAL_KEY_HERE"

# ==========================================

def banner():
    print("=" * 45)
    print("        AbuseTotal - Threat Scanner")
    print("=" * 45)


def convert_timestamp(timestamp):
    try:
        return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return 'N/A'


def validate_apis():
    print("[*] Checking API key validity...")
    vt_url = "https://www.virustotal.com/api/v3/me"
    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    try:
        vt_r = requests.get(vt_url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
        ab_r = requests.get(abuse_url, headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                            params={"ipAddress": "8.8.8.8"})
        if vt_r.status_code == 200 and ab_r.status_code == 200:
            print("[+] API Keys: OK")
            return True
        return False
    except:
        return False


def get_ip_info(target):
    try:
        ip_addr = target if "." in target and target.replace(".", "").isdigit() else socket.gethostbyname(target)
        resp = requests.get(f'https://ipinfo.io/{ip_addr}/json', timeout=5).json()
        return ip_addr, resp.get('city', 'N/A'), resp.get('region', 'N/A'), resp.get('country', 'N/A')
    except:
        return 'N/A', 'N/A', 'N/A', 'N/A'


def scan_target(target, mode):
    endpoint = "domains" if mode == '1' else "ip_addresses"
    vt_url = f"https://www.virustotal.com/api/v3/{endpoint}/{target}"
    vt_resp = requests.get(vt_url, headers={"x-apikey": VIRUSTOTAL_API_KEY})

    if vt_resp.status_code == 429: return "RATE_LIMIT"
    if vt_resp.status_code != 200: return None

    vt_attr = vt_resp.json().get('data', {}).get('attributes', {})
    ip_addr, city, region, country = get_ip_info(target)

    abuse_url = "https://api.abuseipdb.com/api/v2/check"
    ab_resp = requests.get(abuse_url, headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                           params={"ipAddress": ip_addr})

    if ab_resp.status_code == 429: return "RATE_LIMIT"
    ab_data = ab_resp.json().get('data', {}) if ab_resp.status_code == 200 else {}

    return {
        'Target': target,
        'Last Analysis Stats': vt_attr.get('last_analysis_stats', {}),
        'Last Analysis Date': convert_timestamp(vt_attr.get('last_analysis_date', 0)),
        'IP Address': ip_addr,
        'City': city,
        'Region': region,
        'Country': country,
        'Abuse Score': ab_data.get('abuseConfidenceScore', 'N/A'),
        'Abuse Count': ab_data.get('totalReports', 'N/A'),
        'ISP': ab_data.get('isp', 'N/A'),
        'Last Reported At': ab_data.get('lastReportedAt', 'N/A')
    }


def main():
    banner()
    if not validate_apis():
        print("[-] API validation failed.")
        return

    print("\n[1] Domains | [2] IPs")
    choice = input("Choice: ")
    path = input("File path: ")

    if not os.path.exists(path):
        return

    results = []
    with open(path, 'r') as f:
        targets = [l.strip() for l in f if l.strip()]

    for t in targets:
        print(f"[>] Scanning: {t}")
        res = scan_target(t, choice)
        if res == "RATE_LIMIT": break
        if res: results.append(res)
        time.sleep(15.5)

    if results:
        out = "domains_results.csv" if choice == '1' else "ip_results.csv"
        with open(out, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"[+] Saved to {out}")


if __name__ == "__main__":
    main()