"""Minimal PAN-OS XML API client (read-only use).

- API key is read from a key file (mode 600) and never printed or logged.
- Allow-list: every request is checked locally before it is sent. Only log queries and op
  commands starting with <show>, or the pow-performance debug command, are permitted,
  whatever the key's role would allow on the device.
- TLS: devices usually have a self-signed certificate. The SHA-256 fingerprint is pinned
  (stored during 'pan-ngfw-load init'); a changed certificate stops all communication.
"""

from __future__ import annotations

import hashlib
import http.client
import os
import re
import socket
import ssl
import time
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

ALLOWED_OP = (
    re.compile(r"^<show>"),
    re.compile(r"^<debug><dataplane><pow><performance><all/></performance></pow></dataplane></debug>$"),
)
ALLOWED_LOG_ACTIONS = {None, "get", "finish"}
POW_XML = "<debug><dataplane><pow><performance><all/></performance></pow></dataplane></debug>"


class ApiError(RuntimeError):
    pass


def check_allowed(params: dict) -> None:
    """Refuse anything that is not a read: op 'show'/pow-performance, or a log query."""
    t = params.get("type")
    if t == "op" and any(rx.match(params.get("cmd", "")) for rx in ALLOWED_OP):
        return
    if t == "log" and params.get("action") in ALLOWED_LOG_ACTIONS:
        return
    raise ApiError(f"blocked by local allow-list: type={t} {str(params.get('cmd') or params.get('action') or '')[:80]}")


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # replaced by explicit fingerprint pinning
    return ctx


def fetch_fingerprint(host: str, timeout: int = 15) -> str:
    """SHA-256 fingerprint of the device's TLS certificate (no API call)."""
    with socket.create_connection((host, 443), timeout=timeout) as raw:
        with _ctx().wrap_socket(raw, server_hostname=host) as s:
            return hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()


def write_secret(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (text.strip() + "\n").encode())
    finally:
        os.close(fd)


def keygen(host: str, fingerprint: str, user: str, password: str, timeout: int = 60) -> str:
    """Generate an API key (type=keygen) over a connection pinned to `fingerprint`."""
    conn = http.client.HTTPSConnection(host, timeout=timeout, context=_ctx())
    try:
        conn.connect()
        fp = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        if fp != fingerprint:
            raise ApiError("TLS fingerprint mismatch during keygen - aborted")
        body = urllib.parse.urlencode({"type": "keygen", "user": user, "password": password})
        conn.request("POST", "/api/", body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        root = ET.fromstring(resp.read())
    finally:
        conn.close()
    key = root.findtext(".//key")
    if resp.status != 200 or root.get("status") != "success" or not key:
        msg = " ".join(t.strip() for t in root.itertext() if t.strip())
        raise ApiError(f"keygen failed (HTTP {resp.status}): {msg[:200]}")
    return key


class Api:
    def __init__(self, host: str, key_file: Path, fingerprint_file: Path, timeout: int = 120):
        self.host, self.timeout = host, timeout
        if not key_file.exists():
            raise ApiError(f"API key file missing: {key_file}")
        if not fingerprint_file.exists():
            raise ApiError(f"pinned TLS fingerprint missing: {fingerprint_file} (run 'pan-ngfw-load init')")
        self._key = key_file.read_text().strip()
        self._fp = fingerprint_file.read_text().strip()
        self._fp_file = fingerprint_file
        self._ctx = _ctx()

    # --- transport --------------------------------------------------------
    def _request(self, params: dict, *, unchecked: bool = False) -> ET.Element:
        """unchecked=True bypasses the allow-list - only used by 'pan-ngfw-load test' for read-only config probes."""
        if not unchecked:
            check_allowed(params)
        body = urllib.parse.urlencode({**params, "key": self._key})
        conn = http.client.HTTPSConnection(self.host, timeout=self.timeout, context=self._ctx)
        try:
            conn.connect()
            fp = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
            if fp != self._fp:
                raise ApiError(f"TLS certificate of {self.host} changed (pinned {self._fp[:16]}..., now {fp[:16]}...). "
                               f"If expected, re-run 'pan-ngfw-load init' for this device.")
            conn.request("POST", "/api/", body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
            resp = conn.getresponse()
            data = resp.read()
        finally:
            conn.close()
        if resp.status != 200:
            raise ApiError(f"HTTP {resp.status} for type={params.get('type')}")
        root = ET.fromstring(data)
        if root.get("status") != "success":
            msg = " ".join(t.strip() for t in root.itertext() if t.strip())
            raise ApiError(f"API error for type={params.get('type')}: {msg[:300]}")
        return root

    # --- operations -------------------------------------------------------
    def op(self, cmd_xml: str) -> ET.Element:
        """Operational command, e.g. '<show><system><info/></system></show>'. Returns <result>."""
        root = self._request({"type": "op", "cmd": cmd_xml})
        res = root.find("result")
        return res if res is not None else root

    def op_cli(self, cli: str) -> ET.Element:
        """Same, from a CLI string: 'show system info' -> nested XML."""
        return self.op(cli_to_xml(cli))

    def logs(self, log_type: str, query: str = "", nlogs: int = 5000, skip: int = 0,
             poll: float = 2.0, max_wait: int = 600, direction: str = "backward") -> ET.Element | None:
        """Start a log query job and wait for it. Returns the <log> element (newest first by default)."""
        params = {"type": "log", "log-type": log_type, "nlogs": str(nlogs), "skip": str(skip), "dir": direction}
        if query:
            params["query"] = query
        root = self._request(params)
        job = root.findtext(".//job")
        if not job:
            raise ApiError("log query returned no job id")
        t0 = time.time()
        while True:
            r = self._request({"type": "log", "action": "get", "job-id": job})
            if r.findtext(".//job/status") == "FIN":
                return r.find(".//log")
            if time.time() - t0 > max_wait:
                self._request({"type": "log", "action": "finish", "job-id": job})
                raise ApiError(f"log job {job} did not finish within {max_wait}s")
            time.sleep(poll)


def cli_to_xml(cli: str) -> str:
    """'show running resource-monitor minute last 60' -> <show><running><resource-monitor><minute><last>60</last>...

    PAN-OS convention: a token followed by a value-like token (digits / quoted) takes it as text.
    """
    toks = cli.split()
    out, close, i = [], [], 0
    while i < len(toks):
        t = toks[i]
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        if nxt is not None and (nxt.isdigit() or nxt.startswith('"')):
            out.append(f"<{t}>{nxt.strip(chr(34))}</{t}>")
            i += 2
            continue
        out.append(f"<{t}>")
        close.append(f"</{t}>")
        i += 1
    return "".join(out) + "".join(reversed(close))
