import argparse
import json
import socket
import ssl
import whois
import dns.resolver
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import os

def get_ip_and_whois(domain):
    try:
        ip = socket.gethostbyname(domain)
        whois_info = whois.whois(domain)
        return {"ip": ip, "whois": str(whois_info)}
    except Exception as e:
        return {"error": str(e)}

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": cert.get("issuer"),
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter")
                }
    except Exception as e:
        return {"error": str(e)}

def get_dns_records(domain):
    records = {}
    try:
        records["A"] = [r.to_text() for r in dns.resolver.resolve(domain, "A")]
    except: records["A"] = []
    try:
        records["MX"] = [r.to_text() for r in dns.resolver.resolve(domain, "MX")]
    except: records["MX"] = []
    try:
        records["NS"] = [r.to_text() for r in dns.resolver.resolve(domain, "NS")]
    except: records["NS"] = []
    try:
        records["TXT"] = [r.to_text() for r in dns.resolver.resolve(domain, "TXT")]
    except: records["TXT"] = []
    return records

def get_html_metadata(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else ""
        meta_tags = {tag.get("name", ""): tag.get("content", "") for tag in soup.find_all("meta") if tag.get("name")}
        return {"title": title, "meta": meta_tags}
    except Exception as e:
        return {"error": str(e)}

def scan_ports(domain):
    ports = [21, 22, 80, 443, 8080]
    results = {}
    ip = socket.gethostbyname(domain)
    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((ip, port))
            results[str(port)] = "open"
            sock.close()
        except:
            results[str(port)] = "closed"
    return results

def run_scan(domain, deep=False):
    report = {
        "domain": domain,
        "ip_whois": get_ip_and_whois(domain),
        "ssl_info": get_ssl_info(domain),
        "dns_records": get_dns_records(domain),
        "html_metadata": get_html_metadata(domain),
        "ports": scan_ports(domain),
        "vulnerabilities": {"error": "CVE API not implemented"}
    }

    # ذخیره‌سازی گزارش
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs("reports", exist_ok=True)
    report_path = f"reports/{domain}-{timestamp}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)

    # نمایش خروجی در ترمینال
    print(f"\n✅ گزارش ذخیره شد: {report_path}")
    print("\n📊 خروجی اسکن:")
    print(json.dumps(report, indent=4))

def parse_args():
    parser = argparse.ArgumentParser(description="🛡️ Troll-Scan-Pro - Domain Security Scanner")
    parser.add_argument("--url", required=True, help="دامنه مورد نظر برای اسکن")
    parser.add_argument("--deep", action="store_true", help="فعال‌سازی حالت عمیق (در آینده)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run_scan(args.url, args.deep)
