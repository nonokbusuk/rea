#!/usr/bin/env python3
"""Website checker.

Usage:
    python3 scripts/website.py check <url-or-domain> [--timeout SECONDS] [--json]

Performs a passive HTTPS check of a website: DNS resolution, TLS
certificate validity, redirect chain, HTTP status, response timing,
security headers, and page title. No page JavaScript is executed.
"""

import argparse
import json
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def normalize_url(target: str) -> str:
    if "://" not in target:
        target = "https://" + target
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError(f"missing host: {target}")
    return target


def check_dns(host: str, timeout: float) -> dict:
    infos = socket.getaddrinfo(host, None)
    addrs = sorted({info[4][0] for info in infos})
    return {"host": host, "addresses": addrs}


def check_tls(host: str, timeout: float) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            not_after = cert.get("notAfter")
            expiry = ssl.cert_time_to_seconds(not_after) if not_after else None
            days_left = int((expiry - time.time()) / 86400) if expiry else None
            return {
                "subject": dict(x[0] for x in cert.get("subject", ())),
                "issuer": dict(x[0] for x in cert.get("issuer", ())),
                "not_after": not_after,
                "days_left": days_left,
            }


def check_http(url: str, timeout: float, user_agent: str) -> dict:
    started = time.monotonic()
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    redirects = []
    status = None
    final_url = url

    class Recorder(urllib.request.HTTPRedirectHandler):
        def record(self, code, headers):
            redirects.append(
                {"code": code, "location": headers.get("Location")}
            )

        def http_error_301(self, req, fp, code, msg, headers):
            self.record(code, headers)
            return super().http_error_301(req, fp, code, msg, headers)

        def http_error_302(self, req, fp, code, msg, headers):
            self.record(code, headers)
            return super().http_error_302(req, fp, code, msg, headers)

        def http_error_307(self, req, fp, code, msg, headers):
            self.record(code, headers)
            return super().http_error_307(req, fp, code, msg, headers)

        def http_error_308(self, req, fp, code, msg, headers):
            self.record(code, headers)
            return super().http_error_308(req, fp, code, msg, headers)

    opener = urllib.request.build_opener(Recorder())

    try:
        response = opener.open(request, timeout=timeout)
        status = response.status
        final_url = response.geturl()
        body = response.read(512 * 1024)
        headers = dict(response.headers.items())
        elapsed = time.monotonic() - started
    except urllib.error.HTTPError as error:
        status = error.code
        final_url = error.geturl()
        headers = dict(error.headers.items())
        body = b""
        elapsed = time.monotonic() - started

    title = None
    lowered = body[:256 * 1024].decode("utf-8", errors="replace").lower()
    start = lowered.find("<title")
    if start != -1:
        open_end = lowered.find(">", start)
        close = lowered.find("</title>", open_end)
        if open_end != -1 and close != -1:
            title = body[start + (open_end - start) + 1:close].decode(
                "utf-8", errors="replace"
            ).strip()

    header_names = {k.lower(): v for k, v in headers.items()}
    return {
        "status": status,
        "final_url": final_url,
        "redirects": redirects,
        "elapsed_seconds": round(elapsed, 3),
        "body_bytes": len(body),
        "title": title,
        "server": header_names.get("server"),
        "security_headers": {
            name: ("present" if name in header_names else "missing")
            for name in SECURITY_HEADERS
        },
    }


def run_check(target: str, timeout: float, user_agent: str) -> dict:
    url = normalize_url(target)
    host = urllib.parse.urlparse(url).hostname
    result = {"url": url, "host": host}

    try:
        result["dns"] = check_dns(host, timeout)
    except OSError as error:
        result["dns"] = {"host": host, "error": str(error)}
        result["ok"] = False
        return result

    if url.startswith("https://"):
        try:
            result["tls"] = check_tls(host, timeout)
        except (OSError, ssl.SSLError) as error:
            result["tls"] = {"error": str(error)}

    try:
        result["http"] = check_http(url, timeout, user_agent)
    except (OSError, urllib.error.URLError) as error:
        result["http"] = {"error": str(error)}
        result["ok"] = False
        return result

    http = result["http"]
    tls = result.get("tls", {})
    result["ok"] = (
        http.get("status") == 200
        and not http.get("redirects")
        and (not url.startswith("https://") or tls.get("days_left", 0) > 0)
    )
    return result


def print_report(result: dict) -> None:
    print(f"URL: {result['url']}")
    print(f"OK: {'yes' if result.get('ok') else 'no'}")

    dns = result.get("dns", {})
    if "error" in dns:
        print(f"DNS: error ({dns['error']})")
    else:
        print(f"DNS: {', '.join(dns['addresses'])}")

    tls = result.get("tls", {})
    if url_is_https(result["url"]):
        if "error" in tls:
            print(f"TLS: error ({tls['error']})")
        else:
            subject = tls.get("subject", {}).get("commonName", "?")
            issuer = tls.get("issuer", {}).get("organizationName", "?")
            print(
                f"TLS: subject={subject} issuer={issuer} "
                f"expires={tls.get('not_after')} ({tls.get('days_left')} days left)"
            )

    http = result.get("http", {})
    if "error" in http:
        print(f"HTTP: error ({http['error']})")
        return
    print(f"HTTP: {http['status']} in {http['elapsed_seconds']}s "
          f"({http['body_bytes']} bytes)")
    if http.get("redirects"):
        for step in http["redirects"]:
            print(f"  redirect {step['code']} -> {step['location']}")
    print(f"Final URL: {http['final_url']}")
    if http.get("server"):
        print(f"Server: {http['server']}")
    if http.get("title"):
        print(f"Title: {http['title']}")
    missing = [k for k, v in http.get("security_headers", {}).items()
               if v == "missing"]
    present = [k for k, v in http.get("security_headers", {}).items()
               if v == "present"]
    print(f"Security headers present: {', '.join(present) or 'none'}")
    print(f"Security headers missing: {', '.join(missing) or 'none'}")


def url_is_https(url: str) -> bool:
    return urllib.parse.urlparse(url).scheme == "https"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="website.py")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="check a website")
    check.add_argument("target", help="URL or domain to check")
    check.add_argument("--timeout", type=float, default=15.0)
    check.add_argument(
        "--user-agent", default="rea-website-check/1.0", dest="user_agent"
    )
    check.add_argument("--json", action="store_true", dest="as_json")

    args = parser.parse_args(argv)
    try:
        result = run_check(args.target, args.timeout, args.user_agent)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print_report(result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
