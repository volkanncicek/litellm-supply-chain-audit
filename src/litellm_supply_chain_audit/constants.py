"""Known-bad versions and IOC strings for the March 2026 litellm supply-chain incident."""

COMPROMISED_VERSIONS: frozenset[str] = frozenset({"1.82.7", "1.82.8"})
MALICIOUS_DOMAIN: str = "models.litellm.cloud"
PTH_IOC_NAME: str = "litellm_init.pth"
PACKAGE_NAME: str = "litellm"


def remote_host_matches_malicious_ioc(host: object) -> bool:
    """True for the known IOC host (exact or DNS suffix), not other *.litellm.cloud names."""
    h = str(host).strip().lower().rstrip(".")
    if not h:
        return False
    return h == MALICIOUS_DOMAIN or h.endswith("." + MALICIOUS_DOMAIN)


def remote_endpoint_matches_malicious_ioc(remote: object) -> bool:
    """psutil-style remote address: tuple (host, port) or similar."""
    if remote is None:
        return False
    if isinstance(remote, (tuple, list)) and len(remote) >= 1:
        return remote_host_matches_malicious_ioc(remote[0])
    return remote_host_matches_malicious_ioc(remote)
