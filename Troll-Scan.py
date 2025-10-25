import socket, ssl, whois, requests, json, os, argparse, dns.resolver
from bs4 import BeautifulSoup
from datetime import datetime

def get_ip_and_whois(domain):
    ip = socket.gethostbyname(domain)
    data = whois.whois(domain)
    return {"ip": ip, "whois": data.__dict__}

def get_ssl_info(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert()
    except Exception as e:
        return {"error": str(e)}

def get_dns_records(domain):
    records = {}
    for rtype in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [rdata.to_text() for rdata in answers]
        except Exception as e:
            records[rtype] = [f"error: {e}"]
    return records

def scan_ports(domain, ports=[21, 22, 80, 443, 8080]):
    open_ports = []
    for port in ports:
        try:
            sock = socket.create_connection((domain, port), timeout=2)
            open_ports.append(port)
            sock.close()
        except:
            continue
    return open_ports

def get_metadata(domain):
    url = f"http://{domain}"
    try:
        html = requests.get(url, timeout=10).text
        soup = BeautifulSoup(html, 'html.parser')
        return [meta.attrs for meta in soup.find_all('meta')]
    except:
        return []

def check_vulnerabilities(domain):
    url = f"https://cve.circl.lu/api/search/{domain}"
    try:
        response = requests.get(url, timeout=10)
        return response.json().get("results", [])
    except:
        return []

def save_report(domain, data):
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/{domain}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"✅ گزارش ذخیره شد: {filename}")

def run_scan(domain, deep=False):
    print(f"\n🚀 شروع اسکن برای: {domain}")
    result = {
        "ip_whois": get_ip_and_whois(domain),
        "ssl": get_ssl_info(domain),
        "dns": get_dns_records(domain),
        "ports": scan_ports(domain),
        "metadata": get_metadata(domain),
    }
    if deep:
        result["vulnerabilities"] = check_vulnerabilities(domain)
    save_report(domain, result)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Troll-Scan-Pro")
    parser.add_argument("--url", required=True, help="آدرس دامنه")
    parser.add_argument("--deep", action="store_true", help="فعال‌سازی حالت اسکن عمیق")
    args = parser.parse_args()
    run_scan(args.url, args.deep)