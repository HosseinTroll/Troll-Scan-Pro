import socket
import ssl
import json
import datetime
import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup

def get_ip_and_whois(domain):
    try:
        ip = socket.gethostbyname(domain)
        whois_data = whois.whois(domain)
        return {"ip": ip, "whois": str(whois_data)}
    except Exception as e:
        return {"error": str(e)}

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {"error": str(e)}

def get_dns_records(domain):
    records = {}
    try:
        for rtype in ["A", "MX", "NS", "TXT"]:
            answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
            records[rtype] = [str(r.to_text()) for r in answers]
    except Exception as e:
        records["error"] = str(e)
    return records

def get_html_metadata(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else ""
        metas = {meta.get("name", meta.get("property", "unknown")): meta.get("content", "") for meta in soup.find_all("meta")}
        return {"title": title, "meta": metas}
    except Exception as e:
        return {"error": str(e)}

def scan_ports(domain):
    ports = [21, 22, 80, 443, 8080]
    results = {}
    ip = socket.gethostbyname(domain)
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=2):
                results[port] = "open"
        except:
            results[port] = "closed"
    return results

def get_cve_info(domain):
    try:
        response = requests.get(f"https://cve.circl.lu/api/search/{domain}", timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "CVE API failed"}
    except Exception as e:
        return {"error": str(e)}

def run_scan(domain, deep=False):
    report = {
        "domain": domain,
        "ip_whois": get_ip_and_whois(domain),
        "ssl_info": get_ssl_info(domain),
        "dns_records": get_dns_records(domain),
        "html_metadata": get_html_metadata(domain),
        "ports": scan_ports(domain),
    }

    if deep:
        report["vulnerabilities"] = get_cve_info(domain)

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = f"reports/{domain}-{timestamp}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\nReport saved to {report_path}")
    print("\nScan Report:")
    print(json.dumps(report, indent=4))

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Troll-Scan-Pro: Domain Security Scanner")
    parser.add_argument("--url", required=True, help="Target domain to scan")
    parser.add_argument("--deep", action="store_true", help="Enable deep CVE scan")
    args = parser.parse_args()
    run_scan(args.url, args.deep)
