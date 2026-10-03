"""OSINT-X package (solo stdlib). Ver src/python/README.md."""
from . import domain, email, ipinfo, phone, portscan, report, subdomain, url, username
from .common import make_result

__all__ = ["domain", "portscan", "subdomain", "phone", "username",
           "ipinfo", "email", "url", "report", "make_result"]
__version__ = "1.0.0"
