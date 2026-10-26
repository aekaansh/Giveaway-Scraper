"""Hostname helpers shared by store and url_guard.

Uses tldextract's bundled Public Suffix List snapshot only (never fetches the list over
the network). Private suffixes such as github.io are honoured, so `evil.github.io` is
its own registrable domain and blocking it never blocks all of github.io.
"""

from __future__ import annotations

import tldextract

_extract = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


def normalize_host(host: str) -> str:
    return host.strip().rstrip(".").lower()


def registrable_domain(host: str) -> str:
    """`shop.example.co.uk` -> `example.co.uk`.

    Hosts with no known public suffix fall back to their last two labels; IP addresses
    and single-label hosts are returned unchanged.
    """
    host = normalize_host(host)
    ext = _extract(host)
    if ext.top_domain_under_public_suffix:
        return ext.top_domain_under_public_suffix
    if ext.ipv4 or ":" in host or "." not in host:
        return host
    return ".".join(host.split(".")[-2:])


def domain_label(host: str) -> str:
    """The registrable label without suffix: `shop.pokemon.com` -> `pokemon`."""
    return _extract(normalize_host(host)).domain


def host_chain(host: str) -> list[str]:
    """Host and each parent down to the registrable domain, most specific first.

    `a.b.example.com` -> ['a.b.example.com', 'b.example.com', 'example.com']
    """
    host = normalize_host(host)
    labels = host.split(".")
    keep = registrable_domain(host).count(".") + 1
    return [".".join(labels[i:]) for i in range(max(len(labels) - keep, 0) + 1)]
