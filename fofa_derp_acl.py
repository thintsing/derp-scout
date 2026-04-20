#!/usr/bin/env python3
"""derp-scout: search FOFA/exported records for candidate DERP servers, probe them, and emit Tailscale derpMap snippets.

The script is intentionally standard-library only so it can run anywhere Python 3.9+
is available.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import ipaddress
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


DEFAULT_FIELDS = [
    "host",
    "ip",
    "port",
    "protocol",
    "country_name",
    "region",
    "city",
    "as_organization",
    "server",
    "title",
]

DEFAULT_QUERY = 'body="Tailscale" && body="DERP server" && country="HK"'
DEFAULT_TIMEOUT = 4.0
DEFAULT_WORKERS = 24
DEFAULT_MAX_LATENCY_MS = 100.0
DEFAULT_REGION_ID = 900
DEFAULT_REGION_CODE = "custom-derp"
DEFAULT_REGION_NAME = "Custom DERP"
USER_AGENT = "derp-scout/1.0"
FOFA_API = "https://fofa.info/api/v1/search/all"


@dataclass
class Candidate:
    host: str
    hostname: str
    ip: str
    port: int
    protocol: str
    country_name: str
    region: str
    city: str
    as_organization: str
    server: str
    title: str
    domain: str = ""


@dataclass
class ProbeResult:
    host: str
    hostname: str
    ip: str
    port: int
    tcp_ok: bool
    tcp_ms: Optional[float]
    tls_ok: bool
    tls_ms: Optional[float]
    tls_verified: bool
    http_ok: bool
    http_status: Optional[int]
    http_ms: Optional[float]
    http_hint: bool
    stun_ok: bool
    stun_ms: Optional[float]
    selected: bool
    selection_reason: str
    cert_subject: Optional[str]
    cert_san: List[str]
    error: Optional[str]
    source: Dict[str, Any]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search FOFA for DERP candidates and generate Tailscale derpMap snippets."
    )
    parser.add_argument("--fofa-email", default=os.getenv("FOFA_EMAIL"), help="FOFA account email")
    parser.add_argument("--fofa-key", default=os.getenv("FOFA_KEY"), help="FOFA API key")
    parser.add_argument(
        "--input-file",
        help="Read FOFA-exported JSON/JSONL records from a local file instead of calling the FOFA API",
    )
    parser.add_argument("--query", default=DEFAULT_QUERY, help=f'FOFA query, default: {DEFAULT_QUERY!r}')
    parser.add_argument("--size", type=int, default=30, help="FOFA page size")
    parser.add_argument("--page", type=int, default=1, help="FOFA page number")
    parser.add_argument("--full", action="store_true", help="Use FOFA full mode when available")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Probe timeout seconds")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Concurrent probe workers")
    parser.add_argument(
        "--max-latency-ms",
        type=float,
        default=DEFAULT_MAX_LATENCY_MS,
        help="Only select nodes whose measured latency is within this threshold",
    )
    parser.add_argument("--probe-path", default="/derp/probe", help="HTTPS probe path")
    parser.add_argument(
        "--fallback-probe-path",
        default="/",
        help="Fallback HTTPS probe path when the primary path fails",
    )
    parser.add_argument(
        "--require-http-hint",
        action="store_true",
        help="Require response body/headers to look DERP-like before selecting a node",
    )
    parser.add_argument(
        "--require-stun",
        action="store_true",
        help="Require UDP/3478 STUN probing to succeed before selecting a node",
    )
    parser.add_argument(
        "--allow-ip-hostname",
        action="store_true",
        help="Allow IP literals in derpMap HostName. Off by default because TLS validation often breaks.",
    )
    parser.add_argument("--region-id", type=int, default=DEFAULT_REGION_ID, help="Tailscale DERP region id")
    parser.add_argument("--region-code", default=DEFAULT_REGION_CODE, help="Tailscale DERP region code")
    parser.add_argument("--region-name", default=DEFAULT_REGION_NAME, help="Tailscale DERP region name")
    parser.add_argument(
        "--omit-default-regions",
        action="store_true",
        help="Emit OmitDefaultRegions=true in generated derpMap",
    )
    parser.add_argument(
        "--lowercase-keys",
        action="store_true",
        help="Generate lowercase derpMap keys for compatibility with some policy examples",
    )
    parser.add_argument("--json-out", help="Write full probe report to JSON file")
    parser.add_argument("--policy-out", help="Write derpMap snippet to file")
    parser.add_argument(
        "--fields",
        default=",".join(DEFAULT_FIELDS),
        help="FOFA fields to request, comma-separated",
    )
    return parser


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_host(raw_host: str, ip: str, port: int, protocol: str) -> Tuple[str, str, int]:
    value = (raw_host or "").strip()
    hostname = ""
    final_port = port or 443

    if value.startswith("http://") or value.startswith("https://"):
        parsed = urllib.parse.urlparse(value)
        hostname = parsed.hostname or ""
        if parsed.port:
            final_port = parsed.port
    elif value:
        if value.count(":") == 1 and not value.startswith("["):
            host_part, port_part = value.rsplit(":", 1)
            if port_part.isdigit():
                hostname = host_part
                final_port = int(port_part)
            else:
                hostname = value
        else:
            hostname = value

    if not hostname:
        hostname = (ip or "").strip()

    final_host = hostname
    if protocol and protocol.lower() in {"http", "https"}:
        final_host = f"{protocol.lower()}://{hostname}:{final_port}"
    elif final_port:
        final_host = f"{hostname}:{final_port}"

    return final_host, hostname, final_port


def parse_candidate(row: List[Any], fields: List[str]) -> Candidate:
    data = {field: (row[idx] if idx < len(row) else "") for idx, field in enumerate(fields)}
    ip = str(data.get("ip") or "").strip()
    port = int(str(data.get("port") or "443"))
    protocol = str(data.get("protocol") or "https").strip() or "https"
    host, hostname, port = normalize_host(str(data.get("host") or ""), ip, port, protocol)
    return Candidate(
        host=host,
        hostname=hostname,
        ip=ip,
        port=port,
        protocol=protocol,
        country_name=str(data.get("country_name") or ""),
        region=str(data.get("region") or ""),
        city=str(data.get("city") or ""),
        as_organization=str(data.get("as_organization") or ""),
        server=str(data.get("server") or ""),
        title=str(data.get("title") or ""),
        domain="",
    )


def parse_candidate_from_export(record: Dict[str, Any]) -> Candidate:
    ip = str(record.get("ip") or "").strip()
    protocol = str(record.get("protocol") or "https").strip() or "https"
    port = int(str(record.get("port") or "443"))

    raw_host = str(record.get("host") or record.get("link") or record.get("domain") or ip).strip()
    host, hostname, port = normalize_host(raw_host, ip, port, protocol)

    if hostname in {"", "http", "https"}:
        hostname = str(record.get("domain") or ip).strip()
        host, hostname, port = normalize_host(hostname, ip, port, protocol)

    return Candidate(
        host=host,
        hostname=hostname,
        ip=ip,
        port=port,
        protocol=protocol,
        country_name=str(record.get("country") or record.get("country_name") or ""),
        region=str(record.get("region") or ""),
        city=str(record.get("city") or ""),
        as_organization=str(record.get("org") or record.get("as_organization") or ""),
        server=str(record.get("server") or ""),
        title=str(record.get("title") or ""),
        domain=str(record.get("domain") or ""),
    )


def fofa_search(email: str, key: str, query: str, page: int, size: int, fields: List[str], full: bool) -> List[Candidate]:
    qbase64 = base64.b64encode(query.encode("utf-8")).decode("ascii")
    params = {
        "email": email,
        "key": key,
        "qbase64": qbase64,
        "page": str(page),
        "size": str(size),
        "fields": ",".join(fields),
        "full": "true" if full else "false",
    }
    url = f"{FOFA_API}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=15) as resp:
        payload = json.loads(resp.read().decode("utf-8", "replace"))
    if payload.get("error"):
        raise RuntimeError(payload.get("errmsg") or "FOFA API returned an error")
    results = payload.get("results") or []
    return [parse_candidate(row, fields) for row in results]


def load_candidates_from_file(path: str) -> List[Candidate]:
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read().strip()

    if not raw:
        return []

    records: List[Dict[str, Any]] = []
    if raw.startswith("["):
        payload = json.loads(raw)
        if not isinstance(payload, list):
            raise ValueError("JSON file must contain a top-level array")
        records = [item for item in payload if isinstance(item, dict)]
    else:
        for lineno, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {lineno}: {exc}") from exc
            if isinstance(item, dict):
                records.append(item)

    return [parse_candidate_from_export(item) for item in records]


def tcp_probe(hostname: str, port: int, timeout: float) -> Tuple[bool, Optional[float], Optional[str]]:
    start = time.perf_counter()
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            elapsed = (time.perf_counter() - start) * 1000.0
            return True, round(elapsed, 2), None
    except OSError as exc:
        return False, None, str(exc)


def extract_cert_names(cert: Dict[str, Any]) -> Tuple[Optional[str], List[str]]:
    subject = None
    san: List[str] = []
    raw_subject = cert.get("subject") or []
    for item in raw_subject:
        for key, value in item:
            if key == "commonName":
                subject = value
    raw_san = cert.get("subjectAltName") or []
    for key, value in raw_san:
        if key == "DNS":
            san.append(value)
    return subject, san


def tls_probe(hostname: str, port: int, timeout: float) -> Tuple[bool, Optional[float], bool, Optional[str], List[str], Optional[str]]:
    start = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as wrapped:
                cert = wrapped.getpeercert()
        elapsed = (time.perf_counter() - start) * 1000.0
        subject, san = extract_cert_names(cert)
        return True, round(elapsed, 2), True, subject, san, None
    except ssl.SSLCertVerificationError as exc:
        # Retry without verification so we can still extract basic cert metadata.
        try:
            ctx = ssl._create_unverified_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as wrapped:
                    cert = wrapped.getpeercert()
            elapsed = (time.perf_counter() - start) * 1000.0
            subject, san = extract_cert_names(cert)
            return True, round(elapsed, 2), False, subject, san, str(exc)
        except OSError as inner_exc:
            return False, None, False, None, [], str(inner_exc)
    except OSError as exc:
        return False, None, False, None, [], str(exc)


def http_probe(hostname: str, port: int, path: str, timeout: float) -> Tuple[bool, Optional[int], Optional[float], bool, Optional[str]]:
    url = f"https://{hostname}:{port}{path}"
    start = time.perf_counter()
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Connection": "close",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(256).decode("utf-8", "replace")
            headers_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            elapsed = (time.perf_counter() - start) * 1000.0
            hint = "derp" in body.lower() or "derp" in headers_blob.lower() or path == "/derp/probe"
            return True, resp.status, round(elapsed, 2), hint, None
    except urllib.error.HTTPError as exc:
        elapsed = (time.perf_counter() - start) * 1000.0
        body = exc.read(256).decode("utf-8", "replace")
        hint = "derp" in body.lower() or path == "/derp/probe"
        return True, exc.code, round(elapsed, 2), hint, None
    except Exception as exc:  # pragma: no cover - broad because urllib mixes error types
        return False, None, None, False, str(exc)


def stun_probe(hostname: str, port: int, timeout: float) -> Tuple[bool, Optional[float], Optional[str]]:
    request = bytes.fromhex("000100002112A44263C7117E0714278C4A2A6B1B")
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(request, (hostname, port))
        data, _ = sock.recvfrom(2048)
        elapsed = (time.perf_counter() - start) * 1000.0
        if len(data) >= 20 and data[4:8] == bytes.fromhex("2112A442"):
            return True, round(elapsed, 2), None
        return False, None, "received non-STUN response"
    except OSError as exc:
        return False, None, str(exc)
    finally:
        sock.close()


def selection_reason(
    candidate: Candidate,
    latency_ms: Optional[float],
    tls_ok: bool,
    tls_verified: bool,
    http_ok: bool,
    http_hint: bool,
    stun_ok: bool,
    allow_ip_hostname: bool,
    require_http_hint: bool,
    require_stun: bool,
    max_latency_ms: float,
) -> Tuple[bool, str]:
    if not candidate.hostname:
        return False, "missing hostname"
    if is_ip_literal(candidate.hostname) and not allow_ip_hostname:
        return False, "hostname is an IP literal"
    if not tls_ok:
        return False, "TLS handshake failed"
    if not tls_verified:
        return False, "TLS certificate verification failed"
    if not http_ok:
        return False, "HTTPS probe failed"
    if latency_ms is None:
        return False, "latency unavailable"
    if latency_ms > max_latency_ms:
        return False, f"latency {latency_ms:.2f}ms exceeds {max_latency_ms:.2f}ms"
    if require_http_hint and not http_hint:
        return False, "HTTP response does not look like DERP"
    if require_stun and not stun_ok:
        return False, "STUN probe failed"
    return True, "passed"


def probe_candidate(
    candidate: Candidate,
    timeout: float,
    probe_path: str,
    fallback_probe_path: str,
    allow_ip_hostname: bool,
    require_http_hint: bool,
    require_stun: bool,
    max_latency_ms: float,
) -> ProbeResult:
    tcp_ok, tcp_ms, tcp_error = tcp_probe(candidate.hostname, candidate.port, timeout)
    tls_ok = False
    tls_ms = None
    tls_verified = False
    cert_subject = None
    cert_san: List[str] = []
    tls_error: Optional[str] = None
    http_ok = False
    http_status = None
    http_ms = None
    http_hint = False
    http_error: Optional[str] = None
    stun_ok = False
    stun_ms = None
    stun_error: Optional[str] = None

    if tcp_ok:
        tls_ok, tls_ms, tls_verified, cert_subject, cert_san, tls_error = tls_probe(
            candidate.hostname, candidate.port, timeout
        )
    if tls_ok and tls_verified:
        http_ok, http_status, http_ms, http_hint, http_error = http_probe(
            candidate.hostname, candidate.port, probe_path, timeout
        )
        if not http_ok and fallback_probe_path and fallback_probe_path != probe_path:
            http_ok, http_status, http_ms, http_hint, http_error = http_probe(
                candidate.hostname, candidate.port, fallback_probe_path, timeout
            )
    stun_port = 3478
    stun_ok, stun_ms, stun_error = stun_probe(candidate.hostname, stun_port, timeout)
    latency_ms = tls_ms or tcp_ms

    selected, reason = selection_reason(
        candidate=candidate,
        latency_ms=latency_ms,
        tls_ok=tls_ok,
        tls_verified=tls_verified,
        http_ok=http_ok,
        http_hint=http_hint,
        stun_ok=stun_ok,
        allow_ip_hostname=allow_ip_hostname,
        require_http_hint=require_http_hint,
        require_stun=require_stun,
        max_latency_ms=max_latency_ms,
    )
    errors = [msg for msg in [tcp_error, tls_error, http_error, stun_error] if msg]

    return ProbeResult(
        host=candidate.host,
        hostname=candidate.hostname,
        ip=candidate.ip,
        port=candidate.port,
        tcp_ok=tcp_ok,
        tcp_ms=tcp_ms,
        tls_ok=tls_ok,
        tls_ms=tls_ms,
        tls_verified=tls_verified,
        http_ok=http_ok,
        http_status=http_status,
        http_ms=http_ms,
        http_hint=http_hint,
        stun_ok=stun_ok,
        stun_ms=stun_ms,
        selected=selected,
        selection_reason=reason,
        cert_subject=cert_subject,
        cert_san=cert_san,
        error=" | ".join(errors) if errors else None,
        source=asdict(candidate),
    )


def sort_key(result: ProbeResult) -> Tuple[int, float, float]:
    tls_score = 0 if result.tls_verified else 1
    http_score = 0 if result.http_ok else 1
    latency = result.tls_ms or result.tcp_ms or 999999.0
    return tls_score + http_score, latency, result.stun_ms or 999999.0


def make_node_name(region_id: int, index: int) -> str:
    return f"{region_id}a"


def build_derp_map(
    results: Iterable[ProbeResult],
    start_region_id: int,
    region_code: str,
    region_name: str,
    omit_default_regions: bool,
    lowercase_keys: bool,
) -> Dict[str, Any]:
    picked = [item for item in sorted(results, key=sort_key) if item.selected]
    regions: Dict[str, Any] = {}
    for idx, item in enumerate(picked):
        region_id = start_region_id + idx
        node: Dict[str, Any] = {
            "Name": make_node_name(region_id, idx),
            "RegionID": region_id,
            "HostName": item.hostname,
            "DERPPort": item.port,
        }
        if item.ip and not is_ip_literal(item.hostname):
            node["IPv4"] = item.ip
        if item.stun_ok:
            node["STUNPort"] = 3478
        regions[str(region_id)] = {
            "RegionID": region_id,
            "RegionCode": f"{region_code}-{region_id}",
            "RegionName": f"{region_name} {region_id}",
            "Nodes": [node],
        }

    derp_map = {
        "OmitDefaultRegions": omit_default_regions,
        "Regions": regions,
    }
    if lowercase_keys:
        return lowercase_keys_deep({"derpMap": derp_map})
    return {"derpMap": derp_map}


def lowercase_keys_deep(value: Any) -> Any:
    if isinstance(value, dict):
        return {lower_first(k): lowercase_keys_deep(v) for k, v in value.items()}
    if isinstance(value, list):
        return [lowercase_keys_deep(item) for item in value]
    return value


def lower_first(value: str) -> str:
    if not value:
        return value
    return value[:1].lower() + value[1:]


def json_dumps(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def print_summary(results: List[ProbeResult], policy: Dict[str, Any]) -> None:
    total = len(results)
    selected = [item for item in results if item.selected]
    print(f"FOFA candidates: {total}")
    print(f"Selected nodes : {len(selected)}")
    print("")
    for item in sorted(results, key=sort_key):
        status = "PASS" if item.selected else "SKIP"
        latency = item.tls_ms or item.tcp_ms
        region_bits = [item.source.get("country_name"), item.source.get("region"), item.source.get("city")]
        region_text = "/".join(str(part) for part in region_bits if part)
        print(
            f"[{status}] {item.hostname}:{item.port} "
            f"tls={'ok' if item.tls_verified else 'bad'} "
            f"http={item.http_status or '-'} "
            f"stun={'ok' if item.stun_ok else 'no'} "
            f"latency={latency if latency is not None else '-'}ms "
            f"{region_text}"
        )
        if item.error:
            print(f"  reason: {item.selection_reason}; detail: {item.error}")
        else:
            print(f"  reason: {item.selection_reason}")
    print("")
    print("Tailscale derpMap snippet:")
    print(json_dumps(policy))


def write_text(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.input_file:
            candidates = load_candidates_from_file(args.input_file)
        else:
            if not args.fofa_email or not args.fofa_key:
                parser.error(
                    "FOFA credentials are required unless --input-file is used. "
                    "Use --fofa-email/--fofa-key or FOFA_EMAIL/FOFA_KEY."
                )
            fields = [item.strip() for item in args.fields.split(",") if item.strip()]
            candidates = fofa_search(
                email=args.fofa_email,
                key=args.fofa_key,
                query=args.query,
                page=args.page,
                size=args.size,
                fields=fields,
                full=args.full,
            )
    except Exception as exc:
        print(f"Input loading failed: {exc}", file=sys.stderr)
        return 2

    unique: Dict[Tuple[str, int], Candidate] = {}
    for item in candidates:
        key = (item.hostname, item.port)
        if item.hostname and key not in unique:
            unique[key] = item

    results: List[ProbeResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [
            pool.submit(
                probe_candidate,
                candidate,
                args.timeout,
                args.probe_path,
                args.fallback_probe_path,
                args.allow_ip_hostname,
                args.require_http_hint,
                args.require_stun,
                args.max_latency_ms,
            )
            for candidate in unique.values()
        ]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    policy = build_derp_map(
        results=results,
        start_region_id=args.region_id,
        region_code=args.region_code,
        region_name=args.region_name,
        omit_default_regions=args.omit_default_regions,
        lowercase_keys=args.lowercase_keys,
    )

    report = {
        "meta": {
            "source": "file" if args.input_file else "fofa-api",
            "input_file": args.input_file,
            "query": args.query,
            "page": args.page,
            "size": args.size,
            "timeout": args.timeout,
            "workers": args.workers,
            "max_latency_ms": args.max_latency_ms,
            "selected_count": sum(1 for item in results if item.selected),
        },
        "results": [asdict(item) for item in sorted(results, key=sort_key)],
        "policy": policy,
    }

    if args.json_out:
        write_text(args.json_out, json_dumps(report) + "\n")
    if args.policy_out:
        write_text(args.policy_out, json_dumps(policy) + "\n")

    print_summary(results, policy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
