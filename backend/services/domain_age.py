"""
Domain age service for PhishCatcher.

Purpose:
    Determine the registration age of the registrable domain
    associated with a URL using RDAP.

Important:
    Domain age means the age of the registrable domain, not the age
    of an individual subdomain, website deployment, or hosting account.

Examples:
    https://example.com/login
        -> registrable domain: example.com

    https://shop.example.co.uk/login
        -> registrable domain: example.co.uk

    https://my-project.vercel.app/
        -> registrable domain: vercel.app

    The Vercel project itself cannot be assigned a separate RDAP
    registration date because it is a subdomain of vercel.app.
"""

from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Optional
from urllib.parse import urlparse

import requests
import tldextract


RDAP_URL = "https://rdap.org/domain/{domain}"

REQUEST_TIMEOUT = 10


def get_hostname(url: str) -> Optional[str]:
    """
    Extract the hostname from a URL.

    Returns:
        Lowercase hostname, or None if unavailable.
    """
    if not isinstance(url, str) or not url.strip():
        return None

    try:
        parsed = urlparse(url.strip())

        hostname = parsed.hostname

        if not hostname:
            return None

        return hostname.lower().rstrip(".")

    except Exception:
        return None


def get_registered_domain(hostname: str) -> Optional[str]:
    """
    Determine the registrable domain using the Public Suffix List.

    Examples:
        engineers-day-2627-gnits-site.vercel.app
            -> vercel.app

        www.example.com
            -> example.com

        login.example.co.uk
            -> example.co.uk
    """
    if not isinstance(hostname, str) or not hostname.strip():
        return None

    hostname = hostname.strip().lower().rstrip(".")

    try:
        extracted = tldextract.extract(hostname)

        if not extracted.domain or not extracted.suffix:
            return None

        return f"{extracted.domain}.{extracted.suffix}"

    except Exception:
        return None


def parse_rdap_date(value: Any) -> Optional[datetime]:
    """
    Parse an RDAP timestamp into a timezone-aware datetime.
    """
    if not isinstance(value, str) or not value.strip():
        return None

    value = value.strip()

    try:
        # Handle standard ISO-8601 RDAP timestamps.
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except ValueError:
        return None


def get_registration_date(rdap_data: dict) -> Optional[datetime]:
    """
    Extract the original registration date from RDAP data.

    RDAP commonly exposes registration information through
    eventAction values such as:
        registration
        registered
        creation
        created
    """

    events = rdap_data.get("events", [])

    if not isinstance(events, list):
        return None

    preferred_actions = {
        "registration",
        "registered",
        "creation",
        "created",
    }

    candidates = []

    for event in events:
        if not isinstance(event, dict):
            continue

        action = str(event.get("eventAction", "")).strip().lower()
        date_value = event.get("eventDate")

        if action in preferred_actions:
            parsed_date = parse_rdap_date(date_value)

            if parsed_date:
                candidates.append(parsed_date)

    if not candidates:
        return None

    # If multiple valid registration/creation events exist,
    # use the earliest one.
    return min(candidates)


@lru_cache(maxsize=2048)
def lookup_rdap(domain: str) -> Optional[dict]:
    """
    Query RDAP for a registered domain.

    Returns:
        RDAP JSON dictionary, or None if lookup fails.
    """
    if not isinstance(domain, str) or not domain.strip():
        return None

    domain = domain.strip().lower()

    url = RDAP_URL.format(domain=domain)

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "Accept": "application/rdap+json, application/json",
                "User-Agent": "PhishCatcher/1.0",
            },
        )

        if response.status_code != 200:
            return None

        data = response.json()

        if not isinstance(data, dict):
            return None

        return data

    except (requests.RequestException, ValueError):
        return None


def calculate_domain_age(
    registration_date: Optional[datetime],
    reference_date: Optional[datetime] = None,
) -> Optional[int]:
    """
    Calculate domain age in days.

    Args:
        registration_date:
            Original domain registration date.

        reference_date:
            Date used for calculation. Defaults to current UTC time.

    Returns:
        Domain age in whole days, or None if unavailable.
    """
    if registration_date is None:
        return None

    if reference_date is None:
        reference_date = datetime.now(timezone.utc)

    if reference_date.tzinfo is None:
        reference_date = reference_date.replace(tzinfo=timezone.utc)

    reference_date = reference_date.astimezone(timezone.utc)

    if registration_date > reference_date:
        return 0

    return (reference_date - registration_date).days


def get_domain_age_days(url: str) -> Optional[int]:
    """
    Get the registration age of the registrable domain associated
    with a URL.

    Returns:
        Age in days, or None when registration information is
        unavailable.
    """
    hostname = get_hostname(url)

    if not hostname:
        return None

    registered_domain = get_registered_domain(hostname)

    if not registered_domain:
        return None

    rdap_data = lookup_rdap(registered_domain)

    if not rdap_data:
        return None

    registration_date = get_registration_date(rdap_data)

    return calculate_domain_age(registration_date)


def get_domain_age_details(url: str) -> dict:
    """
    Return diagnostic information useful for testing and debugging.

    This is separate from get_domain_age_days() so the prediction
    pipeline can use the simple numeric result.
    """
    hostname = get_hostname(url)

    if not hostname:
        return {
            "url": url,
            "hostname": None,
            "registered_domain": None,
            "registration_date": None,
            "domain_age_days": None,
        }

    registered_domain = get_registered_domain(hostname)

    if not registered_domain:
        return {
            "url": url,
            "hostname": hostname,
            "registered_domain": None,
            "registration_date": None,
            "domain_age_days": None,
        }

    rdap_data = lookup_rdap(registered_domain)

    if not rdap_data:
        return {
            "url": url,
            "hostname": hostname,
            "registered_domain": registered_domain,
            "registration_date": None,
            "domain_age_days": None,
        }

    registration_date = get_registration_date(rdap_data)

    age_days = calculate_domain_age(registration_date)

    return {
        "url": url,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "registration_date": (
            registration_date.isoformat()
            if registration_date
            else None
        ),
        "domain_age_days": age_days,
    }


if __name__ == "__main__":
    # Change this URL when testing another website.
    test_url = "https://myflixerph.com/"

    details = get_domain_age_details(test_url)

    print("\nDomain Age Test")
    print("-" * 50)
    print("URL:", details["url"])
    print("Hostname:", details["hostname"])
    print("Registered domain:", details["registered_domain"])
    print("Registration date:", details["registration_date"])
    print("Domain age (days):", details["domain_age_days"])
    print("-" * 50)