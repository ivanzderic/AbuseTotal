# AbuseTotal

**AbuseTotal** is a CLI tool that unifies **VirusTotal** and **AbuseIPDB** into a single scanner. It quickly checks the reputation security risk and location of domains and IPs in bulk.

---

## Features

* **Dual Integration:** Fetches security stats from VirusTotal and abuse reports from AbuseIPDB.
* **Geolocation:** Detailed data including City, Region, and Country via the ipinfo.io API.
* **Batch Processing:** Scan lists of domains or IPs from a text file automatically.
* **Automatic Export:** Results are saved to CSV files based on your scan type.

---

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ivanzderic/abusetotal.git
    cd abusetotal
    ```

2.  **Install dependencies:**
    ```bash
    pip install requests
    ```

3.  **Configure API Keys:**
    Open `abusetotal.py` and enter your keys at the top of the script:
    ```python
    VIRUSTOTAL_API_KEY = "YOUR_KEY_HERE"
    ABUSEIPDB_API_KEY = "YOUR_KEY_HERE"
    ```
---
## Usage

Run the script and follow the interactive prompts:
```bash
python abusetotal.py
```

## CSV Output Details
The generated CSV files provide the following data points:

Target: The original domain or IP scanned.
- **Last Analysis Stats**: VirusTotal detection breakdown (Malicious, Suspicious, Clean).
- **Last Analysis Date**: The date of the most recent VirusTotal scan.
- **IP Address**: The resolved IP address of the target.
- **City / Region / Country**: Full geographical location data.
- **Abuse Score**: The AbuseIPDB confidence score (0-100%).
- **Abuse Count**: Total reports filed against the target in the last 90 days.
- **ISP**: The Internet Service Provider associated with the target.
- **Last Reported At**: Timestamp of the most recent abuse report.

**API Limits (Free Tier)**
AbuseTotal is optimized for free-tier users. To prevent your API keys from being blocked, the script includes delay between each scan.

- VirusTotal: 4 requests per minute / 500 requests per day.
- AbuseIPDB: 1,000 requests per day.
- IPinfo.io: 50,000 requests per month.
