from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from typing import Any, Dict, List, Tuple

REALM_TOML = os.environ.get("REALM_TOML", "/etc/realm/realm.toml")
SYSTEMD_REALM = os.environ.get("REALM_SERVICE", "realm.service")


def _run(cmd: List[str], timeout: int = 10) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return 1, f"{type(e).__name__}: {e}"


def systemctl_is_active(name: str) -> bool:
    code, out = _run(["systemctl", "is-active", name], timeout=5)
    return code == 0 and out.strip() == "active"


def systemctl_restart(name: str) -> Tuple[bool, str]:
    code, out = _run(["systemctl", "restart", name], timeout=15)
    if code != 0:
        return False, out
    return True, "ok"


def systemctl_status(name: str) -> str:
    _, out = _run(["systemctl", "status", name, "--no-pager"], timeout=10)
    return out


def journal_tail(name: str, lines: int = 200) -> str:
    _, out = _run(["journalctl", "-u", name, "-n", str(lines), "--no-pager"], timeout=10)
    return out


def _normalize_algo(algo: str) -> str:
    s = (algo or "round_robin").lower().strip()
    s = re.sub(r"[_\-\s]", "", s)
    return "iphash" if s in ("iphash", "iph", "ip") else "roundrobin"


def _transport_ws(host: str, path: str, sni: str, insecure: bool) -> str:
    host = host or "www.bing.com"
    path = path or "/ws"
    if not path.startswith("/"):
        path = "/" + path
    sni = sni or host
    opt = f"ws;host={host};path={path};tls;sni={sni}"
    if insecure:
        opt += ";insecure"
    return opt


def build_realm_toml(rules: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    lines.append('[log]')
    lines.append('level = "off"')
    lines.append('output = "stdout"')
    lines.append('')
    lines.append('[network]')
    lines.append('no_tcp = false')
    lines.append('use_udp = true')

    for r in rules:
        if r.get("paused"):
            continue
        targets = [t.strip() for t in (r.get("targets") or []) if str(t).strip()]
        if not targets:
            continue
        lp = int(r.get("local_port"))
        mode = (r.get("mode") or "tcp_udp").lower()
        proto = (r.get("protocol") or "tcp+udp").lower()
        algo = _normalize_algo(str(r.get("algo") or "round_robin"))

        remote = targets[0]
        extras = targets[1:]

        lines.append('')
        lines.append('[[endpoints]]')
        lines.append(f'listen = "0.0.0.0:{lp}"')
        lines.append(f'remote = "{remote}"')
        if extras:
            arr = ", ".join([f'"{x}"' for x in extras])
            lines.append(f'extra_remotes = [{arr}]')
            weights = ", ".join(["1"] * (1 + len(extras)))
            lines.append(f'balance = "{algo}: {weights}"')
        elif algo == "iphash":
            # 单目标但算法为 iphash 时保持一致
            lines.append('balance = "iphash: 1"')

        if mode == "wss_send":
            # client side: remote_transport
            host = str(r.get("wss_host") or "")
            path = str(r.get("wss_path") or "")
            sni = str(r.get("wss_sni") or "")
            insecure = bool(r.get("wss_insecure"))
            lines.append(f'remote_transport = "{_transport_ws(host, path, sni, insecure)}"')
        elif mode == "wss_recv":
            # server side: listen_transport
            path = str(r.get("wss_path") or "/ws")
            if not path.startswith("/"):
                path = "/" + path
            cert = str(r.get("wss_cert") or "/etc/realm-agent/certs/fullchain.pem")
            key = str(r.get("wss_key") or "/etc/realm-agent/certs/privkey.pem")
            lines.append(f'listen_transport = "ws;path={path};tls;cert={cert};key={key}"')

        # protocol network config
        # realm expects endpoints.network table
        lines.append('[endpoints.network]')
        if mode in ("wss_send", "wss_recv"):
            # WSS tunnel itself is TCP
            lines.append('no_tcp = false')
            lines.append('use_udp = false')
        else:
            if proto == "tcp":
                lines.append('no_tcp = false')
                lines.append('use_udp = false')
            elif proto == "udp":
                lines.append('no_tcp = true')
                lines.append('use_udp = true')
            else:
                lines.append('no_tcp = false')
                lines.append('use_udp = true')

    return "\n".join(lines) + "\n"


def write_realm_toml(content: str) -> Tuple[bool, str]:
    os.makedirs(os.path.dirname(REALM_TOML), exist_ok=True)
    try:
        with open(REALM_TOML, "w", encoding="utf-8") as f:
            f.write(content)
        return True, "ok"
    except Exception as e:
        return False, f"write failed: {e}"


def tcp_probe(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def parse_host_port(addr: str) -> Tuple[str, int]:
    # supports host:port
    m = re.match(r"^([^:]+):(\d+)$", addr.strip())
    if not m:
        return addr.strip(), 0
    return m.group(1), int(m.group(2))


def count_connections(local_port: int) -> int:
    # Count established TCP connections where local port matches
    code, out = _run(["ss", "-Hnt", "state", "established", f"( sport = :{local_port} )"], timeout=5)
    if code != 0:
        return 0
    return len([ln for ln in out.splitlines() if ln.strip()])

