"""Scheduled checks against registered assets.

Each check answers one question about one host and returns either nothing (it
passed) or a CheckResult (it did not). Turning those results into findings is
main.py's job; keeping the two apart is what lets the checks be tested without
a network and the bookkeeping be tested without a server.

The checks here are read-only by construction: a TLS handshake and a GET. This
is monitoring the estate, not scanning it — nothing is fuzzed, nothing is
brute-forced, nothing is sent that a browser would not send.
"""
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address

import httpx

from app.config import MONITOR_ALLOW_PRIVATE, MONITOR_TIMEOUT_SECONDS

# Checked on every asset. The first two are the ones that quietly break: a
# certificate nobody renewed, a header somebody removed during a deploy.
SECURITY_HEADERS = {
    "strict-transport-security": ("high", "HSTS"),
    "content-security-policy": ("medium", "Content-Security-Policy"),
    "x-content-type-options": ("low", "X-Content-Type-Options"),
    "x-frame-options": ("low", "X-Frame-Options"),
    "referrer-policy": ("low", "Referrer-Policy"),
}

# How close to expiry is a problem. A certificate is not a surprise: it has a
# date on it, and running out is a self-inflicted outage.
CERT_CRITICAL_DAYS = 0
CERT_HIGH_DAYS = 14
CERT_MEDIUM_DAYS = 30


@dataclass(frozen=True)
class CheckResult:
    """A check that did not pass."""

    check_id: str          # stable: this is what dedupes across runs
    title: str
    severity: str
    detail: str


class TargetRefused(Exception):
    """The host may not be connected to."""


def _split_host(host: str) -> tuple[str, int]:
    if host.count(":") == 1:
        name, _, port = host.partition(":")
        return name, int(port)

    return host, 443


def assert_target_allowed(host: str) -> None:
    """Refuse anything that resolves off the public internet.

    Every address the name resolves to is checked, not just the first: a name
    that answers with one public and one internal address would otherwise walk
    straight through.
    """
    name, port = _split_host(host)

    try:
        infos = socket.getaddrinfo(name, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as error:
        raise TargetRefused(f"Ad çözümlenemedi: {name}") from error

    for info in infos:
        address = ip_address(info[4][0])

        if MONITOR_ALLOW_PRIVATE:
            continue

        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            raise TargetRefused(
                f"{name} özel/dahili bir adrese çözümleniyor ({address}). "
                "Bu kurulum yalnızca genel adresleri kontrol eder."
            )


def check_certificate(host: str) -> CheckResult | None:
    """How long the TLS certificate has left."""
    name, port = _split_host(host)
    context = ssl.create_default_context()

    try:
        with socket.create_connection((name, port), timeout=MONITOR_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=name) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as error:
        return CheckResult(
            "tls-cert-invalid",
            "TLS sertifikası doğrulanamıyor",
            "high",
            str(error),
        )
    except (OSError, ssl.SSLError) as error:
        # Not reachable over TLS at all; the reachability check reports that.
        return CheckResult(
            "tls-unavailable", "TLS bağlantısı kurulamıyor", "medium", str(error)
        )

    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )
    days_left = (expires - datetime.now(timezone.utc)).days

    if days_left <= CERT_CRITICAL_DAYS:
        severity = "critical"
    elif days_left <= CERT_HIGH_DAYS:
        severity = "high"
    elif days_left <= CERT_MEDIUM_DAYS:
        severity = "medium"
    else:
        return None

    when = expires.date().isoformat()
    return CheckResult(
        "tls-cert-expiry",
        "TLS sertifikasının süresi doluyor",
        severity,
        f"{days_left} gün kaldı (bitiş: {when})"
        if days_left > 0
        else f"süresi doldu ({when})",
    )


def check_http(host: str) -> list[CheckResult]:
    """Reachability, and whether the security headers are still there."""
    name, _ = _split_host(host)

    try:
        response = httpx.get(
            f"https://{host}/",
            timeout=MONITOR_TIMEOUT_SECONDS,
            follow_redirects=True,
            headers={"User-Agent": "SecureTask-Monitor"},
        )
    except httpx.HTTPError as error:
        return [
            CheckResult(
                "http-unreachable",
                "Sunucuya HTTPS ile ulaşılamıyor",
                "high",
                str(error)[:500],
            )
        ]

    results = []
    present = {key.lower() for key in response.headers}

    for header, (severity, label) in SECURITY_HEADERS.items():
        if header not in present:
            results.append(
                CheckResult(
                    f"header-{header}",
                    f"{label} başlığı eksik",
                    severity,
                    f"GET https://{name}/ → {response.status_code}, "
                    f"{label} yanıtta yok",
                )
            )

    return results


def run_checks(host: str) -> list[CheckResult]:
    """Every check for one host. Raises TargetRefused before connecting."""
    assert_target_allowed(host)

    results = check_http(host)
    certificate = check_certificate(host)

    if certificate is not None:
        results.append(certificate)

    return results
