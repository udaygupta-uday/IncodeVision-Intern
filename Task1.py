import socket
import requests
from urllib.parse import urlparse

# -----------------------------
# Common Ports to Scan
# -----------------------------
PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP Alternate"
}

# -----------------------------
# Required Security Headers
# -----------------------------
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

# -----------------------------
# Port Scanner
# -----------------------------
def scan_ports(host):
    print("\nScanning Open Ports...\n")

    open_ports = []

    for port, service in PORTS.items():

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((host, port))

        if result == 0:
            open_ports.append((port, service))

        sock.close()

    return open_ports


# -----------------------------
# Header Scanner
# -----------------------------
def check_headers(url):

    print("\nChecking Security Headers...\n")

    missing_headers = []

    try:
        response = requests.get(url, timeout=5)

        headers = response.headers

        for header in SECURITY_HEADERS:

            if header not in headers:
                missing_headers.append(header)

        server = headers.get("Server", "Unknown")

        return missing_headers, server

    except Exception as e:
        print("Error:", e)
        return [], "Unknown"


# -----------------------------
# Report
# -----------------------------
def generate_report(host, open_ports, missing_headers, server):

    print("\n" + "=" * 60)
    print("        BASIC VULNERABILITY SCAN REPORT")
    print("=" * 60)

    print(f"\nTarget : {host}")

    print("\nOpen Ports")

    if open_ports:

        for port, service in open_ports:
            print(f"[+] {port} ({service}) is OPEN")

    else:
        print("No common ports are open.")

    print("\nMissing Security Headers")

    if missing_headers:

        for header in missing_headers:
            print(f"[-] Missing: {header}")

    else:
        print("All important security headers are present.")

    print("\nServer Information")

    print(server)

    print("\nSuggestions")

    if open_ports:
        print("- Close unused ports.")
        print("- Restrict services using firewall.")

    if missing_headers:
        print("- Configure missing HTTP security headers.")
        print("- Enable HTTPS and HSTS.")

    if server != "Unknown":
        print("- Hide server version information if possible.")
        print("- Keep server software updated.")

    print("=" * 60)


# -----------------------------
# Main
# -----------------------------
def main():

    url = input("Enter Website URL (Example: https://example.com): ")

    parsed = urlparse(url)

    host = parsed.hostname

    if not host:
        print("Invalid URL")
        return

    open_ports = scan_ports(host)

    missing_headers, server = check_headers(url)

    generate_report(host, open_ports, missing_headers, server)


if __name__ == "__main__":
    main()
