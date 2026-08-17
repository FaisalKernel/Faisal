# Scrapling evaluation for FAISAL

Date: 2026-08-17

## Sources

- https://github.com/D4Vinci/Scrapling
- https://scrapling.readthedocs.io/en/latest/index.html
- https://pypi.org/project/scrapling/
- https://raw.githubusercontent.com/D4Vinci/Scrapling/main/pyproject.toml
- https://raw.githubusercontent.com/D4Vinci/Scrapling/main/LICENSE
- https://api.github.com/repos/D4Vinci/Scrapling
- https://api.github.com/repos/D4Vinci/Scrapling/releases/latest

## Verified facts

Scrapling is a Python web-scraping and crawling framework. The official repository describes adaptive element tracking, CSS/XPath/text/regex selection, HTTP fetchers, dynamic browser fetchers, concurrent spiders, pause/resume crawl checkpoints, streaming, robots.txt support, throttling, proxy rotation, background XHR capture, and an MCP server. It is user-space software, not a kernel, scheduler, memory manager, accelerator driver, or hardware-isolation layer.

The current official package metadata reports version 0.4.14, Python >=3.10, BSD-3-Clause licensing, and core dependencies including lxml, cssselect, orjson, tld, w3lib, and typing_extensions. Optional fetcher dependencies include curl_cffi, Playwright, Patchright, browserforge, fingerprint data, msgspec, anyio, and protego. Optional AI/shell extras add MCP, markdownify, and IPython. Browser extras require downloading browser binaries and system dependencies.

The GitHub API reports the repository as public, active, non-archived, BSD-3-Clause licensed, Python-based, and updated on 2026-08-17. The latest release is v0.4.14, published 2026-08-10. The repository declares beta development status in pyproject.toml rather than production/stable status.

Static inspection shows browser-based code can launch or connect to browsers through CDP, preserve sessions and cookies, capture XHR responses, use proxies, and expose MCP tools for opening sessions, fetching, extracting, screenshotting, and browser interaction. These capabilities are useful but represent high-authority network/browser boundaries and must not receive model-derived authority directly.

## FAISAL boundary mapping

FAISAL already has a user-space browser service with URL policy, upload/download scope hashes, action decisions, cancellation, hostile-content handling, memory records, event sequences, and kernel capability/network policy fields. FAISAL’s verified-research service stores source URI, source/content/evidence digests, source ranking, confidence, freshness, cross-check count, conflict state, and promotion state.

Scrapling can improve the fetch/parse layer behind these services, but it must not be placed in the kernel and must not bypass FAISAL browser policy, provenance recording, source verification, cgroups, seccomp, Landlock, or cancellation.

## Preliminary conclusion

Adopt Scrapling only as an optional, pinned, isolated user-space fetch/parser adapter for FAISAL’s browser/research services. Do not vendor it into the kernel, enable its MCP server as a privileged global service, connect arbitrary remote CDP browsers, or enable stealth/proxy/anti-bot features by default. The parser-only subset is the lowest-risk useful component. Full fetcher/browser integration requires a dedicated sandbox profile, URL allowlist, egress policy, resource limits, artifact/provenance capture, legal/robots policy, dependency SBOM, and regression tests.

No code has been imported into FAISAL as part of this evaluation.
