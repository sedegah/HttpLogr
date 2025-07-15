import sys
import socket
import ssl
import json
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def print_redirect_chain(response, log):
    log.append("Redirect Chain:")
    for resp in response.history:
        log.append(f"  {resp.status_code} → {resp.headers.get('Location', 'N/A')}")
    log.append(f"  {response.status_code} {response.url}")

def print_headers(headers, log):
    log.append("\nResponse Headers:")
    for k, v in headers.items():
        log.append(f"  {k}: {v}")

def get_ssl_info(hostname, port=443, log=None):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info = {
                    "Subject": cert.get('subject'),
                    "Issuer": cert.get('issuer'),
                    "Valid From": cert.get('notBefore'),
                    "Valid Until": cert.get('notAfter')
                }
                if log is not None:
                    log.append("\nSSL Certificate Info:")
                    for k, v in info.items():
                        log.append(f"  {k}: {v}")
                return info
    except Exception as e:
        if log is not None:
            log.append(f"\nSSL Info could not be retrieved: {e}")
        return None

def resolve_ip(domain, log):
    try:
        ip = socket.gethostbyname(domain)
        log.append(f"\nResolved IP: {ip}")
        return ip
    except socket.gaierror:
        log.append("\nCould not resolve domain.")
        return None

def detect_site_type(html, headers):
    if "x-generator" in headers and "wordpress" in headers["x-generator"].lower():
        return "WordPress"
    if any("wp-content" in line or "wp-includes" in line for line in html.splitlines()):
        return "WordPress"
    if "durable" in html.lower() or "framer" in html.lower() or "webflow" in html.lower():
        return "Possibly AI-generated"
    if "<html" in html and len(html.splitlines()) < 150:
        return "Likely Static"
    return "Unknown"

def get_geolocation(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        if res["status"] == "success":
            return {
                "IP": ip,
                "Country": res["country"],
                "Region": res["regionName"],
                "City": res["city"],
                "ISP": res["isp"]
            }
    except:
        return None
    return None

def write_output(domain, log_lines, data, mode):
    filename = domain.replace(".", "_")
    if mode == "markdown":
        with open(f"{filename}.md", "w", encoding="utf-8") as f:
            for line in log_lines:
                f.write(f"{line}\n")
    elif mode == "json":
        with open(f"{filename}.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        with open(f"{filename}.txt", "w", encoding="utf-8") as f:
            for line in log_lines:
                f.write(f"{line}\n")

def trace(url, export=None, geo=False, verbose=False):
    log = []
    data = {}

    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        try:
            response = requests.get(url, allow_redirects=True, timeout=10, headers=headers)
        except requests.exceptions.SSLError:
            response = requests.get(url, allow_redirects=True, timeout=10, headers=headers, verify=False)
            log.append("\nWarning: SSL verification was disabled due to handshake error.")

        parsed = urlparse(response.url)
        domain = parsed.hostname

        log.append(f"Tracing URL: {url}\n")
        print_redirect_chain(response, log)
        print_headers(response.headers, log)

        html = response.text
        ip = resolve_ip(domain, log)
        ssl_info = get_ssl_info(domain, log=log)
        site_type = detect_site_type(html, response.headers)

        log.append(f"\nSite Technology: {site_type}")

        if geo and ip:
            geo_info = get_geolocation(ip)
            if geo_info:
                log.append("\nGeolocation:")
                for k, v in geo_info.items():
                    log.append(f"  {k}: {v}")
                data["Geolocation"] = geo_info

        data.update({
            "Final URL": response.url,
            "Status Code": response.status_code,
            "IP": ip,
            "SSL Info": ssl_info,
            "Headers": dict(response.headers),
            "Site Type": site_type
        })

        write_output(domain, log, data, export)
        if verbose:
            print("\n".join(log))

        print(f"\nOutput saved as {domain.replace('.', '_')}.{export if export else 'txt'}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="URL to trace")
    parser.add_argument("--export", choices=["markdown", "json"], help="Export format")
    parser.add_argument("--geo", action="store_true", help="Include IP geolocation")
    parser.add_argument("--verbose", action="store_true", help="Print all output to console")

    args = parser.parse_args()
    trace(args.url, export=args.export, geo=args.geo, verbose=args.verbose)
