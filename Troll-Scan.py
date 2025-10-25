import os
import socket
import ssl
import json
import datetime
import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup

# ساخت پوشه reports اگر وجود نداشت
os.makedirs("reports", exist_ok=True)

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
        metas = {
            meta.get("name", meta.get("property", "unknown")): meta.get("content", "")
            for meta in soup.find_all("meta")
        }
        return {"title": title, "meta": metas}
    except Exception as e:
        return {"error": str(e)}
