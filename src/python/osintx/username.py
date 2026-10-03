"""OSINT-X 05-USERNAME: presencia pública en ~15 plataformas.

Check por HTTP GET (status 200 vs 404). 403/429/bloqueos se reportan
como 'unknown' con error explícito; no se hace bypass ni login.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import re

from .common import http_get, make_result

USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,39}$")

PLATFORMS: list[tuple[str, str]] = [
    ("GitHub",    "https://github.com/{u}"),
    ("GitLab",    "https://gitlab.com/{u}"),
    ("X",         "https://x.com/{u}"),
    ("Reddit",    "https://www.reddit.com/user/{u}/"),
    ("Medium",    "https://medium.com/@{u}"),
    ("Dev.to",    "https://dev.to/{u}"),
    ("PyPI",      "https://pypi.org/user/{u}/"),
    ("npm",       "https://www.npmjs.com/~{u}"),
    ("DockerHub", "https://hub.docker.com/u/{u}/"),
    ("Codepen",   "https://codepen.io/{u}"),
    ("Twitch",    "https://www.twitch.tv/{u}"),
    ("TikTok",    "https://www.tiktok.com/@{u}"),
    ("YouTube",   "https://www.youtube.com/@{u}"),
    ("Kaggle",    "https://www.kaggle.com/{u}"),
    ("HackerOne", "https://hackerone.com/{u}"),
]


def _check_platform(name: str, tpl: str, u: str) -> tuple[dict, str | None]:
    url = tpl.format(u=u)
    r = http_get(url, timeout=10)
    err = None
    if r["ok"] and r["status"] == 200:
        state = "found"
    elif r["status"] == 404:
        state = "not_found"
    else:
        state = "unknown"
        detail = r['error'] or f"HTTP {r['status']}"
        err = f"{name}: {detail} -> unknown (sin bypass)"
    item = {"platform": name, "url_observed": url,
            "http_status_observed": r["status"], "state_inferred": state}
    return item, err


def lookup(username: str) -> dict:
    errors: list[str] = []
    sources: list[str] = []
    u = (username or "").strip().lstrip("@")
    if not u or not USER_RE.match(u):
        return make_result(username, {"input_observed": username}, [],
                           [f"username inválido: {username!r} (1-39 chars [A-Za-z0-9._-])"], "error")

    # Consultar concurrentemente manteniendo el orden original
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(_check_platform, name, tpl, u) for name, tpl in PLATFORMS]
        results_and_errors = [f.result() for f in futures]

    results = []
    for item, err in results_and_errors:
        results.append(item)
        sources.append(item["url_observed"])
        if err:
            errors.append(err)

    found = sum(1 for x in results if x["state_inferred"] == "found")
    data = {"username_observed": u, "found_count_observed": found, "results": results,
            "note": "state_inferred deriva solo del status HTTP público; 'unknown' no confirma ni niega."}
    return make_result(u, data, sources, errors, "ok" if found or not errors else "partial")
