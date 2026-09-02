"""
sources.py

Owns all intelligence-source integrations for ThreatLens:
- Input validation/normalization helpers
- VirusTotal integration
- WHOIS integration
- The SOURCES registry that the orchestration layer iterates over

This module must never import from app.py.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, date
from typing import Any, Callable
from urllib.parse import urlparse

import requests
import streamlit as st
import whois as whois_lib


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

HTTP_TIMEOUT_SECONDS = 10
VT_BASE_URL = "https://www.virustotal.com/api/v3"

VALID_VERDICTS = {"safe", "suspicious", "malicious", "informational", "unknown"}


# --------------------------------------------------------------------------
# Input validation / normalization helpers
# --------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def is_valid_ip(value: str) -> bool:
    """Return True if value is a syntactically valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    """Return True if value looks like a syntactically valid domain name."""
    value = value.strip().rstrip(".")
    if not value or " " in value:
        return False
    return bool(_DOMAIN_RE.match(value))


def is_valid_url(value: str) -> bool:
    """Return True if value looks like a syntactically valid http(s) URL."""
    value = value.strip()
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    hostname = parsed.hostname or ""
    return is_valid_domain(hostname) or is_valid_ip(hostname)


def validate_target(target: str, target_type: str) -> tuple[bool, str]:
    """
    Validate a target string against its declared type.

    Returns (is_valid, error_message). error_message is empty when valid.
    """
    target = (target or "").strip()
    if not target:
        return False, "Target value cannot be empty."

    if target_type == "IP Address":
        if is_valid_ip(target):
            return True, ""
        return False, f"'{target}' is not a valid IPv4/IPv6 address."

    if target_type == "Domain":
        if is_valid_domain(target):
            return True, ""
        return False, f"'{target}' is not a valid domain name."

    if target_type == "URL":
        if is_valid_url(target):
            return True, ""
        return False, f"'{target}' is not a valid http(s) URL."

    return False, f"Unsupported target type: {target_type}"


def extract_hostname(target: str, target_type: str) -> str | None:
    """
    Extract the relevant hostname/domain for a target, used primarily by
    WHOIS. Returns None when no hostname is applicable (e.g. bare IP).
    """
    target = target.strip()
    if target_type == "Domain":
        return target.rstrip(".")
    if target_type == "URL":
        parsed = urlparse(target)
        return parsed.hostname
    if target_type == "IP Address":
        return None
    return None


def _get_secret(key: str) -> str | None:
    """
    Resolve an API key by checking, in order:
    1. A key the user entered in this browser session (st.session_state).
    2. A key configured server-side in Streamlit secrets (.streamlit/secrets.toml).

    This lets each visitor supply their own key via the UI, while still
    allowing an operator to pre-configure a shared key via secrets.
    """
    session_value = st.session_state.get(key)
    if session_value:
        return str(session_value)

    try:
        value = st.secrets.get(key)
    except Exception:
        value = None
    if not value:
        return None
    return str(value)


def _error_result(source_name: str, message: str) -> dict[str, Any]:
    """Build a normalized error result for a source."""
    return {
        "source": source_name,
        "status": "error",
        "verdict": "unknown",
        "summary": message,
        "details": {},
    }


def _serialize_dates(obj: Any) -> Any:
    """Convert datetime/date objects (and lists of them) into ISO strings."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, list):
        cleaned = [_serialize_dates(item) for item in obj]
        # Collapse single-item lists for readability.
        return cleaned[0] if len(cleaned) == 1 else cleaned
    return obj


# --------------------------------------------------------------------------
# VirusTotal integration
# --------------------------------------------------------------------------

def _vt_endpoint(target: str, target_type: str) -> tuple[str, dict[str, Any] | None]:
    """
    Return (url, json_body) for the VirusTotal request appropriate to the
    target type. json_body is non-None only for the URL submission flow.
    """
    if target_type == "IP Address":
        return f"{VT_BASE_URL}/ip_addresses/{target}", None
    if target_type == "Domain":
        return f"{VT_BASE_URL}/domains/{target}", None
    if target_type == "URL":
        # VirusTotal requires URLs to be looked up by a base64 (URL-safe,
        # no padding) encoded identifier.
        import base64

        url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
        return f"{VT_BASE_URL}/urls/{url_id}", None
    raise ValueError(f"Unsupported target type: {target_type}")


def _vt_verdict_from_stats(stats: dict[str, int]) -> str:
    """Map VirusTotal's last_analysis_stats into our normalized verdict."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    return "safe"


def get_virustotal(target: str, target_type: str) -> dict[str, Any]:
    """
    Query VirusTotal for reputation data on an IP, domain, or URL.

    Returns a normalized result dict; never raises.
    """
    source_name = "VirusTotal"
    api_key = _get_secret("VIRUSTOTAL_API_KEY")
    if not api_key:
        return _error_result(
            source_name,
            "VirusTotal API key is not configured. Add VIRUSTOTAL_API_KEY to secrets.",
        )

    try:
        url, _ = _vt_endpoint(target, target_type)
    except ValueError as exc:
        return _error_result(source_name, str(exc))

    headers = {"x-apikey": api_key}

    try:
        # For URL targets, VirusTotal only has data if the URL was
        # previously submitted/scanned. Submit it first to get/refresh an
        # analysis, then fetch the normalized report by its ID.
        if target_type == "URL":
            submit_resp = requests.post(
                f"{VT_BASE_URL}/urls",
                headers=headers,
                data={"url": target},
                timeout=HTTP_TIMEOUT_SECONDS,
            )
            if submit_resp.status_code == 401:
                return _error_result(source_name, "Invalid VirusTotal API key.")
            if submit_resp.status_code == 429:
                return _error_result(source_name, "VirusTotal rate limit exceeded.")
            if submit_resp.status_code >= 400:
                return _error_result(
                    source_name,
                    f"VirusTotal URL submission failed (HTTP {submit_resp.status_code}).",
                )

        response = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT_SECONDS)
    except requests.exceptions.Timeout:
        return _error_result(source_name, "VirusTotal request timed out.")
    except requests.exceptions.RequestException as exc:
        return _error_result(source_name, f"VirusTotal request failed: {exc}")

    if response.status_code == 401:
        return _error_result(source_name, "Invalid VirusTotal API key.")
    if response.status_code == 404:
        return _error_result(
            source_name, "VirusTotal has no record for this target yet."
        )
    if response.status_code == 429:
        return _error_result(source_name, "VirusTotal rate limit exceeded.")
    if response.status_code >= 400:
        return _error_result(
            source_name, f"VirusTotal returned an error (HTTP {response.status_code})."
        )

    try:
        payload = response.json()
        attributes = payload["data"]["attributes"]
    except (ValueError, KeyError, TypeError):
        return _error_result(source_name, "VirusTotal returned an unexpected response.")

    stats = attributes.get("last_analysis_stats", {}) or {}
    if not stats:
        return {
            "source": source_name,
            "status": "success",
            "verdict": "unknown",
            "summary": "VirusTotal has no analysis statistics for this target.",
            "details": {},
        }

    verdict = _vt_verdict_from_stats(stats)
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1

    reputation = attributes.get("reputation")
    categories = attributes.get("categories") or {}

    # Collect a short, bounded list of engines that flagged this target so
    # Gemini/UI can explain *why*, without dumping the full raw payload.
    flagged_engines: list[str] = []
    results = attributes.get("last_analysis_results", {}) or {}
    for engine_name, engine_result in results.items():
        category = engine_result.get("category")
        if category in ("malicious", "suspicious"):
            flagged_engines.append(f"{engine_name}: {category}")
        if len(flagged_engines) >= 10:
            break

    summary = (
        f"{malicious}/{total} engines flagged this as malicious, "
        f"{suspicious}/{total} as suspicious."
    )

    details: dict[str, Any] = {
        "detection_stats": stats,
        "reputation_score": reputation,
        "categories": categories,
    }
    if flagged_engines:
        details["flagged_by"] = flagged_engines

    return {
        "source": source_name,
        "status": "success",
        "verdict": verdict,
        "summary": summary,
        "details": details,
    }


# --------------------------------------------------------------------------
# WHOIS integration
# --------------------------------------------------------------------------

_WHOIS_FIELDS = (
    "registrar",
    "creation_date",
    "expiration_date",
    "updated_date",
    "name_servers",
    "org",
    "country",
    "status",
)


def get_whois(target: str, target_type: str) -> dict[str, Any]:
    """
    Query WHOIS registration data for a domain (or the hostname extracted
    from a URL). Not applicable to bare IP addresses.

    Returns a normalized result dict; never raises.
    """
    source_name = "WHOIS"

    hostname = extract_hostname(target, target_type)
    if not hostname:
        return {
            "source": source_name,
            "status": "success",
            "verdict": "informational",
            "summary": "WHOIS is not applicable to raw IP addresses.",
            "details": {},
        }

    try:
        record = whois_lib.whois(hostname)
    except Exception as exc:  # whois lookups fail in many library-specific ways
        return _error_result(source_name, f"WHOIS lookup failed: {exc}")

    if not record or not getattr(record, "domain_name", None):
        return {
            "source": source_name,
            "status": "success",
            "verdict": "unknown",
            "summary": f"No WHOIS registration data found for '{hostname}'.",
            "details": {},
        }

    details: dict[str, Any] = {}
    for field in _WHOIS_FIELDS:
        value = getattr(record, field, None)
        if value:
            details[field] = _serialize_dates(value)

    if not details:
        return {
            "source": source_name,
            "status": "success",
            "verdict": "unknown",
            "summary": f"WHOIS record for '{hostname}' is present but redacted/private.",
            "details": {},
        }

    registrar = details.get("registrar", "an unknown registrar")
    creation = details.get("creation_date", "an unknown date")
    summary = f"Registered via {registrar} on {creation}."

    return {
        "source": source_name,
        "status": "success",
        "verdict": "informational",
        "summary": summary,
        "details": details,
    }


# --------------------------------------------------------------------------
# Source registry
# --------------------------------------------------------------------------

SOURCES: dict[str, Callable[[str, str], dict[str, Any]]] = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
