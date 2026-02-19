from __future__ import annotations

from collections import OrderedDict, deque
import hashlib
import hmac
import ipaddress
import json
import os
import random
import socket
import ssl
import struct
import subprocess
import threading
import time
import weakref
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if s in ('1', 'true', 'yes', 'y', 'on'):
        return True
    if s in ('0', 'false', 'no', 'n', 'off'):
        return False
    return bool(default)


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(str(os.getenv(name, str(default))).strip() or default)
    except Exception:
        v = int(default)
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    return int(v)


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    try:
        v = float(str(os.getenv(name, str(default))).strip() or default)
    except Exception:
        v = float(default)
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    return float(v)


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v or '').strip().lower() in ('1', 'true', 'yes', 'y', 'on')

# -----------------------------
# Intranet tunnel (A<->B)
# -----------------------------
# Goals:
# - Deterministic handshakes (HMAC) to avoid "connected but not really" black boxes
# - Ping/pong heartbeats + stale-session cleanup to avoid zombie sessions
# - Rich runtime state for panel "握手检查"
# - Keep deps minimal (no cryptography)

INTRA_DIR = Path(os.getenv('REALM_AGENT_INTRANET_DIR', '/etc/realm-agent/intranet'))
SERVER_KEY = INTRA_DIR / 'server.key'
SERVER_CERT = INTRA_DIR / 'server.crt'
SERVER_PEM = INTRA_DIR / 'server.pem'
LOG_FILE = INTRA_DIR / 'intranet.log'

DEFAULT_TUNNEL_PORT = int(os.getenv('REALM_INTRANET_TUNNEL_PORT', '18443'))
OPEN_TIMEOUT = float(os.getenv('REALM_INTRANET_OPEN_TIMEOUT', '8.0'))
TCP_BACKLOG = int(os.getenv('REALM_INTRANET_TCP_BACKLOG', '256'))
UDP_SESSION_TTL = float(os.getenv('REALM_INTRANET_UDP_TTL', '60.0'))
MAX_FRAME = int(os.getenv('REALM_INTRANET_MAX_UDP_FRAME', '65535'))
SOCKET_RCVBUF = _env_int('REALM_INTRANET_SOCKET_RCVBUF', 1024 * 1024, 0, 32 * 1024 * 1024)
SOCKET_SNDBUF = _env_int('REALM_INTRANET_SOCKET_SNDBUF', 1024 * 1024, 0, 32 * 1024 * 1024)
TCP_NODELAY = _env_bool('REALM_INTRANET_TCP_NODELAY', True)
TCP_QUICKACK = _env_bool('REALM_INTRANET_TCP_QUICKACK', False)
TCP_RELAY_CHUNK = _env_int('REALM_INTRANET_TCP_RELAY_CHUNK', 128 * 1024, 8 * 1024, 1024 * 1024)
TCP_RELAY_STOP_WAIT = _env_float('REALM_INTRANET_TCP_RELAY_STOP_WAIT', 0.05, 0.01, 1.0)
TCP_RELAY_DRAIN_TIMEOUT = _env_float('REALM_INTRANET_TCP_RELAY_DRAIN_TIMEOUT', 15.0, 1.0, 120.0)
UDP_BRIDGE_STOP_WAIT = _env_float('REALM_INTRANET_UDP_BRIDGE_STOP_WAIT', 0.2, 0.02, 2.0)
DIAL_CONNECT_TIMEOUT = _env_float('REALM_INTRANET_DIAL_CONNECT_TIMEOUT', 6.0, 1.0, 60.0)
DIAL_TLS_TIMEOUT = _env_float('REALM_INTRANET_DIAL_TLS_TIMEOUT', 8.0, 1.0, 60.0)
SERVER_TLS_HANDSHAKE_TIMEOUT = _env_float('REALM_INTRANET_SERVER_TLS_HANDSHAKE_TIMEOUT', 8.0, 1.0, 60.0)
FIRST_PACKET_TIMEOUT = _env_float('REALM_INTRANET_FIRST_PACKET_TIMEOUT', 5.0, 1.0, 30.0)
FIRST_PACKET_MAX = _env_int('REALM_INTRANET_FIRST_PACKET_MAX', 65536, 256, 1024 * 1024)
MAX_ACCEPT_WORKERS = _env_int('REALM_INTRANET_MAX_ACCEPT_WORKERS', 512, 8, 8192)
MAX_ACTIVE_FLOWS = _env_int('REALM_INTRANET_MAX_ACTIVE_FLOWS', 1024, 8, 65535)
MAX_CLIENT_OPEN_WORKERS = _env_int('REALM_INTRANET_MAX_CLIENT_OPEN_WORKERS', 512, 8, 8192)
MAX_TCP_LISTENER_WORKERS = _env_int(
    'REALM_INTRANET_MAX_TCP_LISTENER_WORKERS',
    max(256, MAX_ACTIVE_FLOWS * 2),
    32,
    16384,
)
CONTROL_RECV_TIMEOUT = _env_float('REALM_INTRANET_CONTROL_RECV_TIMEOUT', 2.0, 0.2, 10.0)
NONCE_TTL_SEC = _env_int('REALM_INTRANET_NONCE_TTL_SEC', 600, 60, 3600)
NONCE_LRU_PER_TOKEN = _env_int('REALM_INTRANET_NONCE_LRU_PER_TOKEN', 2048, 64, 65535)
LOG_ROTATE_BYTES = _env_int('REALM_INTRANET_LOG_ROTATE_BYTES', 10 * 1024 * 1024, 0, 1024 * 1024 * 1024)
LOG_ROTATE_KEEP = _env_int('REALM_INTRANET_LOG_ROTATE_KEEP', 5, 1, 20)

# Handshake/heartbeat
INTRANET_MAGIC = os.getenv('REALM_INTRANET_MAGIC', 'realm-intranet')
INTRANET_PROTO_VER = int(os.getenv('REALM_INTRANET_PROTO_VER', '3'))
HELLO_TIMEOUT = float(os.getenv('REALM_INTRANET_HELLO_TIMEOUT', '6.0'))
PING_INTERVAL = float(os.getenv('REALM_INTRANET_PING_INTERVAL', '15.0'))
PONG_TIMEOUT = float(os.getenv('REALM_INTRANET_PONG_TIMEOUT', '45.0'))
SESSION_STALE = float(os.getenv('REALM_INTRANET_SESSION_STALE', '65.0'))
TS_SKEW_SEC = int(os.getenv('REALM_INTRANET_TS_SKEW_SEC', '300'))

# Keep TLS as secure default.
# Set REALM_INTRANET_ALLOW_PLAINTEXT=1 only for break-glass compatibility.
ALLOW_PLAINTEXT_FALLBACK = _env_bool('REALM_INTRANET_ALLOW_PLAINTEXT', False)
REQUIRE_TLS_SERVER = _env_bool('REALM_INTRANET_REQUIRE_TLS', True)

# Log can be disabled in extreme IO constrained env
ENABLE_LOG = _env_bool('REALM_INTRANET_LOG', True)

_BALANCE_ALGO_MAP = {
    'roundrobin': 'roundrobin',
    'iphash': 'iphash',
    'leastconn': 'least_conn',
    'leastlatency': 'least_latency',
    'consistenthash': 'consistent_hash',
    'randomweight': 'random_weight',
}
_WEIGHTED_BALANCE_ALGOS = {'roundrobin', 'random_weight'}
LB_LATENCY_EMA_ALPHA = _env_float('REALM_INTRANET_LB_LATENCY_EMA_ALPHA', 0.28, 0.05, 0.95)
LB_LATENCY_FAIL_PENALTY_MS = _env_int('REALM_INTRANET_LB_LATENCY_FAIL_MS', 2000, 200, 15000)
LB_LATENCY_TIMEOUT_PENALTY_MS = _env_int('REALM_INTRANET_LB_LATENCY_TIMEOUT_MS', 4000, 500, 30000)
DIAL_HAPPY_EYEBALLS = _env_bool('REALM_INTRANET_HAPPY_EYEBALLS', True)
DIAL_HAPPY_EYEBALLS_STAGGER_MS = _env_int('REALM_INTRANET_HAPPY_EYEBALLS_STAGGER_MS', 220, 20, 1000)
DIAL_HAPPY_EYEBALLS_MAX_ADDRS = _env_int('REALM_INTRANET_HAPPY_EYEBALLS_MAX_ADDRS', 8, 2, 32)
LB_ROUTE_RTT_REF_MS = _env_int('REALM_INTRANET_ROUTE_RTT_REF_MS', 180, 20, 5000)
LB_ROUTE_JITTER_REF_MS = _env_int('REALM_INTRANET_ROUTE_JITTER_REF_MS', 60, 5, 2000)
LB_ROUTE_MIN_SAMPLES = _env_int('REALM_INTRANET_ROUTE_MIN_SAMPLES', 4, 1, 100)
LB_ROUTE_EXPLORE_EVERY = _env_int('REALM_INTRANET_ROUTE_EXPLORE_EVERY', 12, 1, 200)
LB_ROUTE_RTT_WEIGHT = _env_float('REALM_INTRANET_ROUTE_RTT_WEIGHT', 0.58, 0.05, 0.95)
LB_ROUTE_JITTER_WEIGHT = _env_float('REALM_INTRANET_ROUTE_JITTER_WEIGHT', 0.17, 0.01, 0.95)
LB_ROUTE_LOSS_WEIGHT = _env_float('REALM_INTRANET_ROUTE_LOSS_WEIGHT', 0.25, 0.01, 0.95)


def _now() -> float:
    return time.time()


def _now_ms() -> int:
    return int(_now() * 1000)


_LOG_LOCK = threading.Lock()


def _normalize_balance_algo(raw: Any) -> str:
    s = str(raw or '').strip().lower()
    for ch in ('_', '-', ' '):
        s = s.replace(ch, '')
    return str(_BALANCE_ALGO_MAP.get(s) or 'roundrobin')


def _parse_balance(balance: Any, remote_count: int) -> Tuple[str, List[int]]:
    n = max(0, int(remote_count))
    if n <= 0:
        return 'roundrobin', []
    txt = str(balance or 'roundrobin').strip()
    if not txt:
        txt = 'roundrobin'
    if ':' not in txt:
        algo = _normalize_balance_algo(txt)
        return algo, [1] * n

    left, right = txt.split(':', 1)
    algo = _normalize_balance_algo(left)
    if algo not in _WEIGHTED_BALANCE_ALGOS:
        return algo, [1] * n
    raw = [x.strip() for x in right.replace('，', ',').split(',') if x.strip()]
    ws: List[int] = []
    for item in raw:
        if not item.isdigit():
            return algo, [1] * n
        v = int(item)
        if v <= 0:
            return algo, [1] * n
        ws.append(v)
    if len(ws) != n:
        ws = [1] * n
    return algo, ws


def _addr_source_key(addr: Any) -> str:
    try:
        if isinstance(addr, tuple) and addr:
            return str(addr[0] or '').strip()
    except Exception:
        return ''
    return ''


def _pick_weighted_random_index(weights: List[int]) -> int:
    if not weights:
        return 0
    total = 0
    safe: List[int] = []
    for w in weights:
        v = max(1, int(w))
        safe.append(v)
        total += v
    if total <= 0:
        return 0
    point = random.uniform(0.0, float(total))
    acc = 0.0
    for idx, w in enumerate(safe):
        acc += float(w)
        if point <= acc:
            return int(idx)
    return max(0, len(safe) - 1)


def _pick_weighted_rr_index(weights: List[int], current: List[int]) -> int:
    if not weights:
        return 0
    n = len(weights)
    if len(current) != n:
        current[:] = [0] * n
    total = 0
    best_idx = 0
    best_val = None
    for i in range(n):
        w = max(1, int(weights[i]))
        total += w
        current[i] = int(current[i]) + w
        val = int(current[i])
        if best_val is None or val > int(best_val):
            best_val = val
            best_idx = i
    current[best_idx] = int(current[best_idx]) - int(total)
    return int(best_idx)


def _pick_consistent_hash_index(remotes: List[str], key: str, fallback_idx: int = 0) -> int:
    n = len(remotes)
    if n <= 0:
        return 0
    if not key:
        return int(max(0, fallback_idx) % n)
    best_idx = 0
    best_score = -1
    for idx, remote in enumerate(remotes):
        payload = f'{key}|{remote}'.encode('utf-8', errors='ignore')
        digest = hashlib.sha1(payload).digest()
        score = int.from_bytes(digest[:8], byteorder='big', signed=False)
        if score > best_score:
            best_score = score
            best_idx = idx
    return int(best_idx)


def _latency_sample_ms(started_at: float, *, ok: bool, timeout: bool = False) -> float:
    elapsed = float(max(1, int(max(0.0, (_now() - float(started_at))) * 1000.0)))
    if ok:
        return elapsed
    penalty = float(LB_LATENCY_TIMEOUT_PENALTY_MS if timeout else LB_LATENCY_FAIL_PENALTY_MS)
    return max(elapsed, penalty)


def _update_latency_ema(store: Dict[str, float], target: str, sample_ms: float) -> None:
    t = str(target or '').strip()
    if not t:
        return
    cur = float(max(1.0, sample_ms))
    prev = store.get(t)
    if prev is None:
        store[t] = cur
        return
    alpha = float(LB_LATENCY_EMA_ALPHA)
    store[t] = (float(prev) * (1.0 - alpha)) + (cur * alpha)


def _normalize_route_weights() -> Tuple[float, float, float]:
    rw = max(0.0, float(LB_ROUTE_RTT_WEIGHT))
    jw = max(0.0, float(LB_ROUTE_JITTER_WEIGHT))
    lw = max(0.0, float(LB_ROUTE_LOSS_WEIGHT))
    total = rw + jw + lw
    if total <= 0.0:
        return 0.58, 0.17, 0.25
    return rw / total, jw / total, lw / total


LB_ROUTE_RTT_WEIGHT_N, LB_ROUTE_JITTER_WEIGHT_N, LB_ROUTE_LOSS_WEIGHT_N = _normalize_route_weights()


def _route_quality_score(rtt_ms: Optional[float], jitter_ms: Optional[float], loss_ratio: Optional[float], samples: int) -> Optional[float]:
    if rtt_ms is None:
        return None
    rtt_v = max(1.0, float(rtt_ms))
    jitter_v = float(jitter_ms) if jitter_ms is not None else (rtt_v * 0.08)
    jitter_v = max(0.0, jitter_v)
    if loss_ratio is None:
        loss_v = 0.0
    else:
        loss_v = max(0.0, min(1.0, float(loss_ratio)))

    rtt_factor = float(LB_ROUTE_RTT_REF_MS) / (float(LB_ROUTE_RTT_REF_MS) + rtt_v)
    jitter_factor = float(LB_ROUTE_JITTER_REF_MS) / (float(LB_ROUTE_JITTER_REF_MS) + jitter_v)
    loss_factor = 1.0 - loss_v

    score = (
        (rtt_factor * float(LB_ROUTE_RTT_WEIGHT_N))
        + (jitter_factor * float(LB_ROUTE_JITTER_WEIGHT_N))
        + (loss_factor * float(LB_ROUTE_LOSS_WEIGHT_N))
    )
    conf = min(1.0, float(max(0, int(samples))) / float(max(1, int(LB_ROUTE_MIN_SAMPLES))))
    score = score * (0.6 + 0.4 * conf)
    return max(0.0, min(1.0, float(score)))


def _update_loss_ema(store: Dict[str, float], target: str, ok: bool) -> None:
    t = str(target or '').strip()
    if not t:
        return
    sample = 0.0 if bool(ok) else 1.0
    prev = store.get(t)
    if prev is None:
        store[t] = sample
        return
    alpha = float(LB_LATENCY_EMA_ALPHA)
    out = (float(prev) * (1.0 - alpha)) + (sample * alpha)
    store[t] = max(0.0, min(1.0, out))


def _update_target_quality(
    latency_store: Dict[str, float],
    jitter_store: Dict[str, float],
    loss_store: Dict[str, float],
    last_sample_store: Dict[str, float],
    sample_count_store: Dict[str, int],
    target: str,
    sample_ms: float,
    *,
    ok: bool,
) -> None:
    t = str(target or '').strip()
    if not t:
        return
    _update_latency_ema(latency_store, t, sample_ms)
    prev = last_sample_store.get(t)
    if prev is not None:
        _update_latency_ema(jitter_store, t, abs(float(sample_ms) - float(prev)))
    elif t not in jitter_store:
        jitter_store[t] = max(1.0, float(sample_ms) * 0.05)
    last_sample_store[t] = float(max(1.0, sample_ms))
    _update_loss_ema(loss_store, t, bool(ok))
    sample_count_store[t] = int(sample_count_store.get(t, 0)) + 1


def _family_label(family: int) -> str:
    if int(family) == int(getattr(socket, 'AF_INET6', 10)):
        return 'ipv6'
    if int(family) == int(getattr(socket, 'AF_INET', 2)):
        return 'ipv4'
    return str(int(family))


def _sockaddr_label(sockaddr: Any) -> str:
    try:
        if isinstance(sockaddr, tuple):
            if len(sockaddr) >= 2:
                host = str(sockaddr[0] or '').strip()
                port = int(sockaddr[1] or 0)
                if (':' in host) and (not host.startswith('[')):
                    return f'[{host}]:{port}'
                return f'{host}:{port}'
    except Exception:
        pass
    return str(sockaddr)


def _resolve_addrinfos(host: str, port: int, sock_type: int, *, max_addrs: int = 0) -> List[Tuple[int, int, int, Any]]:
    infos = socket.getaddrinfo(host, int(port), socket.AF_UNSPEC, sock_type)
    seen: set[Tuple[int, int, int, Any]] = set()
    ordered: List[Tuple[int, int, int, Any]] = []
    for family, stype, proto, _canon, sockaddr in infos:
        key = (int(family), int(stype), int(proto), sockaddr)
        if key in seen:
            continue
        seen.add(key)
        ordered.append((int(family), int(stype), int(proto), sockaddr))

    ipv6: List[Tuple[int, int, int, Any]] = []
    ipv4: List[Tuple[int, int, int, Any]] = []
    other: List[Tuple[int, int, int, Any]] = []
    for item in ordered:
        if item[0] == socket.AF_INET6:
            ipv6.append(item)
        elif item[0] == socket.AF_INET:
            ipv4.append(item)
        else:
            other.append(item)

    out: List[Tuple[int, int, int, Any]] = []
    for idx in range(max(len(ipv6), len(ipv4))):
        if idx < len(ipv6):
            out.append(ipv6[idx])
        if idx < len(ipv4):
            out.append(ipv4[idx])
    out.extend(other)

    limit = int(max_addrs or 0)
    if limit > 0 and len(out) > limit:
        out = out[:limit]
    return out


def _dial_tcp_seq(infos: List[Tuple[int, int, int, Any]], timeout: float) -> Tuple[Optional[socket.socket], str, Dict[str, Any]]:
    info: Dict[str, Any] = {
        'race_mode': 'sequential',
        'happy_eyeballs_enabled': False,
        'resolved': int(len(infos)),
        'attempts': 0,
    }
    t0 = time.monotonic()
    last_err = 'dial_failed'
    for family, stype, proto, sockaddr in infos:
        info['attempts'] = int(info.get('attempts', 0)) + 1
        s: Optional[socket.socket] = None
        try:
            s = socket.socket(family, stype, proto)
            _set_socket_buffers(s)
            s.settimeout(float(timeout))
            s.connect(sockaddr)
            s.settimeout(None)
            info['winner_family'] = _family_label(family)
            info['winner_addr'] = _sockaddr_label(sockaddr)
            info['duration_ms'] = int(max(0.0, (time.monotonic() - t0) * 1000.0))
            return s, '', info
        except Exception as exc:
            last_err = str(exc)
            _safe_close(s)
    info['duration_ms'] = int(max(0.0, (time.monotonic() - t0) * 1000.0))
    return None, last_err, info


def _dial_tcp_happy_eyeballs(infos: List[Tuple[int, int, int, Any]], timeout: float) -> Tuple[Optional[socket.socket], str, Dict[str, Any]]:
    base_info: Dict[str, Any] = {
        'race_mode': 'happy_eyeballs',
        'happy_eyeballs_enabled': True,
        'resolved': int(len(infos)),
        'attempts': 0,
    }
    t0 = time.monotonic()
    if len(infos) <= 1:
        s, err, info = _dial_tcp_seq(infos, timeout)
        info['race_mode'] = 'sequential'
        info['happy_eyeballs_enabled'] = False
        return s, err, info

    stop = threading.Event()
    lock = threading.Lock()
    winner: List[Tuple[socket.socket, str, str]] = []
    errors: List[str] = []
    stagger_s = max(0.02, float(DIAL_HAPPY_EYEBALLS_STAGGER_MS) / 1000.0)

    def _attempt(idx: int, item: Tuple[int, int, int, Any]) -> None:
        delay = float(idx) * stagger_s
        if delay > 0.0 and stop.wait(delay):
            return
        if stop.is_set():
            return
        family, stype, proto, sockaddr = item
        s: Optional[socket.socket] = None
        try:
            with lock:
                base_info['attempts'] = int(base_info.get('attempts', 0)) + 1
            s = socket.socket(family, stype, proto)
            _set_socket_buffers(s)
            s.settimeout(float(timeout))
            s.connect(sockaddr)
            s.settimeout(None)
            with lock:
                if (not winner) and (not stop.is_set()):
                    winner.append((s, _family_label(family), _sockaddr_label(sockaddr)))
                    stop.set()
                    return
        except Exception as exc:
            with lock:
                errors.append(str(exc))
        _safe_close(s)

    workers: List[threading.Thread] = []
    for idx, info in enumerate(infos):
        th = threading.Thread(target=_attempt, args=(idx, info), daemon=True)
        th.start()
        workers.append(th)

    deadline = time.monotonic() + float(timeout) + (stagger_s * float(max(0, len(infos) - 1))) + 0.25
    while time.monotonic() < deadline:
        if stop.wait(0.02):
            break
        if not any(th.is_alive() for th in workers):
            break

    if winner:
        ws, wf, wa = winner[0]
        base_info['winner_family'] = wf
        base_info['winner_addr'] = wa
        base_info['duration_ms'] = int(max(0.0, (time.monotonic() - t0) * 1000.0))
        for th in workers:
            try:
                th.join(timeout=0.01)
            except Exception:
                pass
        return ws, '', base_info

    stop.set()
    for th in workers:
        try:
            th.join(timeout=0.02)
        except Exception:
            pass
    if errors:
        base_info['duration_ms'] = int(max(0.0, (time.monotonic() - t0) * 1000.0))
        return None, errors[0], base_info
    base_info['duration_ms'] = int(max(0.0, (time.monotonic() - t0) * 1000.0))
    return None, 'dial_failed', base_info


def _dial_tcp_target(host: str, port: int, timeout: float) -> Tuple[Optional[socket.socket], str, Dict[str, Any]]:
    base: Dict[str, Any] = {
        'host': str(host or ''),
        'port': int(port),
        'happy_eyeballs_enabled': bool(DIAL_HAPPY_EYEBALLS),
        'race_mode': ('happy_eyeballs' if DIAL_HAPPY_EYEBALLS else 'sequential'),
        'attempts': 0,
        'resolved': 0,
    }
    try:
        infos = _resolve_addrinfos(host, int(port), socket.SOCK_STREAM, max_addrs=DIAL_HAPPY_EYEBALLS_MAX_ADDRS)
    except Exception as exc:
        base['error'] = f'resolve_failed: {exc}'
        return None, str(base.get('error') or 'resolve_failed'), base
    if not infos:
        base['error'] = 'resolve_no_addr'
        return None, 'resolve_no_addr', base
    base['resolved'] = int(len(infos))
    if DIAL_HAPPY_EYEBALLS and len(infos) > 1:
        s, err, info = _dial_tcp_happy_eyeballs(infos, timeout)
    else:
        s, err, info = _dial_tcp_seq(infos, timeout)
    if isinstance(info, dict):
        base.update(info)
    return s, err, base


def _dial_udp_target(host: str, port: int, timeout: float) -> Tuple[Optional[socket.socket], str, Dict[str, Any]]:
    base: Dict[str, Any] = {
        'host': str(host or ''),
        'port': int(port),
        'attempts': 0,
        'resolved': 0,
    }
    try:
        infos = _resolve_addrinfos(host, int(port), socket.SOCK_DGRAM, max_addrs=DIAL_HAPPY_EYEBALLS_MAX_ADDRS)
    except Exception as exc:
        base['error'] = f'resolve_failed: {exc}'
        return None, str(base.get('error') or 'resolve_failed'), base
    if not infos:
        base['error'] = 'resolve_no_addr'
        return None, 'resolve_no_addr', base
    base['resolved'] = int(len(infos))

    last_err = 'dial_failed'
    for family, stype, proto, sockaddr in infos:
        s: Optional[socket.socket] = None
        try:
            base['attempts'] = int(base.get('attempts', 0)) + 1
            s = socket.socket(family, stype, proto)
            _set_socket_buffers(s)
            s.settimeout(float(timeout))
            s.connect(sockaddr)
            s.settimeout(None)
            base['winner_family'] = _family_label(family)
            base['winner_addr'] = _sockaddr_label(sockaddr)
            return s, '', base
        except Exception as exc:
            last_err = str(exc)
            _safe_close(s)
    base['error'] = last_err
    return None, last_err, base


def _rotate_logs_locked() -> None:
    if LOG_ROTATE_BYTES <= 0:
        return
    try:
        if (not LOG_FILE.exists()) or LOG_FILE.stat().st_size < LOG_ROTATE_BYTES:
            return
    except Exception:
        return

    try:
        oldest = INTRA_DIR / f'{LOG_FILE.name}.{LOG_ROTATE_KEEP}'
        if oldest.exists():
            oldest.unlink()
    except Exception:
        pass

    for i in range(LOG_ROTATE_KEEP - 1, 0, -1):
        src = INTRA_DIR / f'{LOG_FILE.name}.{i}'
        dst = INTRA_DIR / f'{LOG_FILE.name}.{i + 1}'
        try:
            if src.exists():
                src.replace(dst)
        except Exception:
            pass

    try:
        LOG_FILE.replace(INTRA_DIR / f'{LOG_FILE.name}.1')
    except Exception:
        pass


def _log(event: str, **fields: Any) -> None:
    if not ENABLE_LOG:
        return
    try:
        INTRA_DIR.mkdir(parents=True, exist_ok=True)
        payload = {'ts': int(_now()), 'event': event}
        payload.update(fields)
        line = (json.dumps(payload, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
        with _LOG_LOCK:
            _rotate_logs_locked()
            with open(LOG_FILE, 'ab', buffering=0) as f:
                f.write(line)
    except Exception:
        pass


def _mask_token(t: str) -> str:
    t = str(t or '')
    if len(t) <= 10:
        return t
    return t[:4] + '…' + t[-4:]


def _json_line(obj: Dict[str, Any]) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')


def _recv_line(sock: Any, max_len: int = 65536) -> str:
    """socket/SSLSocket compatible line reader (buffered).

    The old implementation used recv(1) in a loop, which is extremely slow.
    We keep a per-socket buffer so we can recv in chunks while still preserving
    bytes after the newline for the next call.

    IMPORTANT: callers rely on socket.timeout being raised when there is no
    incoming data (they set short timeouts to periodically wake up), so we
    preserve that behaviour.
    """
    with _RECV_LINE_BUFS_LOCK:
        buf = _RECV_LINE_BUFS.get(sock)
        if buf is None:
            buf = bytearray()
            _RECV_LINE_BUFS[sock] = buf

    while True:
        nl = buf.find(b'\n')
        if nl != -1:
            line = bytes(buf[:nl])
            del buf[: nl + 1]
            return line.decode('utf-8', errors='ignore').strip()

        if len(buf) >= max_len:
            line = bytes(buf[:max_len])
            del buf[:max_len]
            return line.decode('utf-8', errors='ignore').strip()

        try:
            chunk = sock.recv(min(4096, max_len - len(buf)))
        except socket.timeout:
            # IMPORTANT: allow callers that use settimeout() to distinguish
            # between "no data yet" (timeout) and a real disconnect.
            raise
        except Exception:
            break

        if not chunk:
            break

        buf.extend(chunk)

    # EOF / error: flush buffer and drop state
    with _RECV_LINE_BUFS_LOCK:
        _RECV_LINE_BUFS.pop(sock, None)

    return buf.decode('utf-8', errors='ignore').strip()


def _safe_close(s: Any) -> None:
    try:
        s.close()
    except Exception:
        pass


def shutil_which(cmd: str) -> Optional[str]:
    # local minimal which, avoid importing shutil at module import time in agent
    try:
        import shutil
        return shutil.which(cmd)
    except Exception:
        return None


def _server_cert_pair_usable() -> bool:
    try:
        if (not SERVER_CERT.exists()) or (not SERVER_KEY.exists()):
            return False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(SERVER_CERT), keyfile=str(SERVER_KEY))
        return True
    except Exception:
        return False


def _write_server_pem() -> None:
    try:
        pem = (SERVER_KEY.read_text(encoding='utf-8') + '\n' + SERVER_CERT.read_text(encoding='utf-8')).strip() + '\n'
        SERVER_PEM.write_text(pem, encoding='utf-8')
    except Exception:
        pass


def ensure_server_cert() -> None:
    """Ensure we have a self-signed cert for intranet tunnel server.

    We intentionally avoid extra Python dependencies (cryptography).
    If openssl is unavailable and no pre-provisioned cert/key exist, TLS cannot be enabled.
    """
    try:
        INTRA_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        return

    pair_exists = SERVER_CERT.exists() and SERVER_KEY.exists()
    if pair_exists and _server_cert_pair_usable():
        # Keep bundled PEM in sync (used by some tooling / debug flows).
        if (not SERVER_PEM.exists()) or (SERVER_PEM.stat().st_size <= 0):
            _write_server_pem()
        return
    if pair_exists:
        # Self-heal corrupted / mismatched cert-key pair.
        for p in (SERVER_CERT, SERVER_KEY, SERVER_PEM):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass

    openssl = shutil_which('openssl')
    if not openssl:
        return

    try:
        cmd = [
            openssl,
            'req',
            '-x509',
            '-nodes',
            '-newkey',
            'rsa:2048',
            '-keyout',
            str(SERVER_KEY),
            '-out',
            str(SERVER_CERT),
            '-days',
            '3650',
            '-subj',
            '/CN=realm-intranet',
        ]
        subprocess.run(cmd, capture_output=True, text=True, check=False)
        if _server_cert_pair_usable():
            _write_server_pem()
            return
        # Avoid leaving a broken cert pair behind; next round can retry generation.
        for p in (SERVER_CERT, SERVER_KEY, SERVER_PEM):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass
    except Exception:
        return


def load_server_cert_pem() -> str:
    try:
        ensure_server_cert()
        return SERVER_CERT.read_text(encoding='utf-8')
    except Exception:
        return ''


def server_tls_ready() -> bool:
    try:
        return _mk_server_ssl_context() is not None
    except Exception:
        return False


def _mk_server_ssl_context() -> Optional[ssl.SSLContext]:
    ensure_server_cert()
    if not SERVER_CERT.exists() or not SERVER_KEY.exists():
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.load_cert_chain(certfile=str(SERVER_CERT), keyfile=str(SERVER_KEY))
        return ctx
    except Exception:
        return None


# Per-socket buffers for _recv_line (avoid 1-byte recv loop)
_RECV_LINE_BUFS = weakref.WeakKeyDictionary()  # sock -> bytearray
_RECV_LINE_BUFS_LOCK = threading.Lock()


def _mk_client_ssl_context(server_cert_pem: Optional[str], require_verify: bool = False) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.check_hostname = False
    if server_cert_pem:
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.load_verify_locations(cadata=server_cert_pem)
        except Exception as exc:
            raise ValueError(f'invalid_server_cert_pem: {exc}') from exc
    else:
        if require_verify:
            raise ValueError('server_cert_missing')
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _set_socket_buffers(sock_obj: Any) -> None:
    if SOCKET_RCVBUF > 0:
        try:
            sock_obj.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, int(SOCKET_RCVBUF))
        except Exception:
            pass
    if SOCKET_SNDBUF > 0:
        try:
            sock_obj.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, int(SOCKET_SNDBUF))
        except Exception:
            pass


def _set_tcp_low_latency(sock_obj: Any) -> None:
    if TCP_NODELAY:
        try:
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
    if TCP_QUICKACK and hasattr(socket, 'TCP_QUICKACK'):
        try:
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        except Exception:
            pass


def _set_keepalive(sock_obj: Any) -> None:
    _set_socket_buffers(sock_obj)
    _set_tcp_low_latency(sock_obj)
    try:
        sock_obj.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        pass
    # Best effort for Linux/macOS. Ignore failures.
    try:
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        elif hasattr(socket, 'TCP_KEEPALIVE'):
            # macOS/BSD use TCP_KEEPALIVE as idle time option.
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 30)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception:
        pass


def _hmac_sig(token: str, node_id: int, ts: int, nonce: str) -> str:
    msg = f"{INTRANET_MAGIC}|{INTRANET_PROTO_VER}|{node_id}|{ts}|{nonce}".encode('utf-8')
    return hmac.new(token.encode('utf-8'), msg, hashlib.sha256).hexdigest()


def _parse_nonneg_int(v: Any) -> int:
    try:
        iv = int(v)
    except Exception:
        return 0
    return iv if iv > 0 else 0


def _normalize_str_list(raw: Any, max_items: int = 64, item_max_len: int = 128) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    rows: List[Any]
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, str):
        rows = [x for x in str(raw).replace(',', '\n').splitlines()]
    else:
        rows = []
    for row in rows:
        s = str(row or '').strip()
        if not s:
            continue
        if len(s) > item_max_len:
            s = s[:item_max_len]
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= max_items:
            break
    return out


def _parse_hour_range(txt: str) -> Optional[Tuple[int, int]]:
    s = str(txt or '').strip()
    if not s:
        return None
    if '-' not in s:
        return None
    left, right = s.split('-', 1)
    left = left.strip()
    right = right.strip()
    if not left or not right:
        return None

    def _to_minute(part: str) -> Optional[int]:
        if ':' not in part:
            return None
        hh, mm = part.split(':', 1)
        if (not hh.isdigit()) or (not mm.isdigit()):
            return None
        h = int(hh)
        m = int(mm)
        if h < 0 or h > 23 or m < 0 or m > 59:
            return None
        return h * 60 + m

    lmin = _to_minute(left)
    rmin = _to_minute(right)
    if lmin is None or rmin is None:
        return None
    return lmin, rmin


def _compile_hour_windows(raw: Any) -> List[Tuple[int, int]]:
    rows = _normalize_str_list(raw, max_items=16, item_max_len=16)
    out: List[Tuple[int, int]] = []
    for row in rows:
        it = _parse_hour_range(row)
        if it is not None:
            out.append(it)
    return out


def _match_hour_windows(windows: List[Tuple[int, int]], now_ts: Optional[float] = None) -> bool:
    if not windows:
        return True
    ts = float(now_ts) if now_ts is not None else _now()
    lt = time.localtime(ts)
    minute = int(lt.tm_hour) * 60 + int(lt.tm_min)
    for left, right in windows:
        if left <= right:
            if left <= minute <= right:
                return True
        else:
            # Cross-day window, e.g. 23:00-06:00
            if minute >= left or minute <= right:
                return True
    return False


def _compile_ip_networks(raw: Any) -> List[Any]:
    rows = _normalize_str_list(raw, max_items=128, item_max_len=64)
    out: List[Any] = []
    for row in rows:
        txt = row
        if '/' not in txt:
            # host ip -> strict /32 or /128 network
            if ':' in txt:
                txt = f'{txt}/128'
            else:
                txt = f'{txt}/32'
        try:
            out.append(ipaddress.ip_network(txt, strict=False))
        except Exception:
            continue
    return out


def _ip_acl_allowed(addr: str, allow_nets: List[Any], deny_nets: List[Any]) -> bool:
    ip_txt = str(addr or '').strip()
    if not ip_txt:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_txt)
    except Exception:
        return False

    for net in deny_nets:
        try:
            if ip_obj in net:
                return False
        except Exception:
            continue
    if not allow_nets:
        return True
    for net in allow_nets:
        try:
            if ip_obj in net:
                return True
        except Exception:
            continue
    return False


class _ConnRateLimiter:
    """Simple per-second connection rate limiter."""

    def __init__(self, rate_per_sec: int):
        self.rate = max(0, int(rate_per_sec))
        self._lock = threading.Lock()
        self._events = deque()

    def allow(self) -> bool:
        if self.rate <= 0:
            return True
        now = _now()
        cutoff = now - 1.0
        with self._lock:
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            if len(self._events) >= self.rate:
                return False
            self._events.append(now)
            return True


class _ByteRateLimiter:
    """Thread-safe token-bucket limiter for aggregate byte throughput."""

    def __init__(self, bytes_per_sec: int):
        self.rate = max(0, int(bytes_per_sec))
        self.capacity = max(self.rate, 65536) if self.rate > 0 else 0
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, n: int) -> None:
        if self.rate <= 0:
            return
        need = max(0, int(n))
        if need <= 0:
            return
        while True:
            sleep_s = 0.0
            with self._lock:
                now = time.monotonic()
                elapsed = max(0.0, now - self._last)
                self._last = now
                if elapsed > 0.0:
                    self._tokens = min(float(self.capacity), self._tokens + elapsed * float(self.rate))
                if self._tokens >= float(need):
                    self._tokens -= float(need)
                    return
                short = float(need) - self._tokens
                self._tokens = 0.0
                sleep_s = short / float(self.rate)
            time.sleep(max(0.001, min(0.2, sleep_s)))


@dataclass
class IntranetRule:
    sync_id: str
    role: str  # 'server' or 'client'
    listen: str
    protocol: str
    balance: str
    remotes: List[str]
    token: str
    peer_node_id: int
    peer_host: str
    tunnel_port: int
    server_cert_pem: str = ''  # for client verification
    tokens: List[str] = field(default_factory=list)
    tls_verify: bool = False
    qos_bandwidth_kbps: int = 0
    qos_max_conns: int = 0
    qos_conn_rate: int = 0
    acl_allow_sources: List[str] = field(default_factory=list)
    acl_deny_sources: List[str] = field(default_factory=list)
    acl_allow_hours: List[str] = field(default_factory=list)
    acl_allow_tokens: List[str] = field(default_factory=list)


class _ControlSession:
    def __init__(self, token: str, node_id: int, sock: Any, dial_mode: str, legacy: bool = False):
        self.token = token
        self.tokens: set[str] = {token}
        self.node_id = node_id
        self.sock = sock
        self.dial_mode = dial_mode
        self.legacy = legacy

        self.lock = threading.Lock()
        self.closed = False

        self.connected_at = _now()
        self.hello_ok_at = self.connected_at
        self.last_seen = self.connected_at
        self.last_ping_at = 0.0
        self.rtt_ms: Optional[int] = None

    def send(self, obj: Dict[str, Any]) -> bool:
        if self.closed:
            return False
        try:
            data = _json_line(obj)
            with self.lock:
                self.sock.sendall(data)
            return True
        except Exception:
            self.closed = True
            _safe_close(self.sock)
            return False

    def close(self, reason: str = '') -> None:
        self.closed = True
        try:
            _safe_close(self.sock)
        finally:
            _log('control_closed', token=_mask_token(self.token), node_id=self.node_id, reason=reason)


class _TunnelServer:
    """A-side tunnel server listening on TCP/TLS port (default 18443).

    Accepts both control connections (type=hello) and data connections (type=data/data_udp).
    """

    def __init__(self, port: int):
        self.port = int(port)
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None
        self._janitor_th: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._tls_required = bool(REQUIRE_TLS_SERVER)
        self._ssl_ctx = _mk_server_ssl_context()
        self._startup_error = ''

        self._allowed_tokens_lock = threading.Lock()
        self._allowed_tokens: set[str] = set()

        self._sessions_lock = threading.Lock()
        self._sessions: Dict[str, _ControlSession] = {}  # token -> session

        self._pending_lock = threading.Lock()
        self._pending: Dict[Tuple[str, str], Dict[str, Any]] = {}  # (token, conn_id) -> {event, client_sock, proto, udp_sender}

        self._accept_sem = threading.BoundedSemaphore(MAX_ACCEPT_WORKERS)
        self._flow_sem = threading.BoundedSemaphore(MAX_ACTIVE_FLOWS)

        self._nonce_lock = threading.Lock()
        self._recent_nonces: Dict[str, OrderedDict[str, float]] = {}

        self._stats_lock = threading.Lock()
        self._accept_active = 0
        self._accept_peak = 0
        self._flow_active = 0
        self._flow_peak = 0
        self._tcp_active = 0
        self._tcp_peak = 0
        self._udp_active = 0
        self._udp_peak = 0
        self._open_total = 0
        self._open_success = 0
        self._open_fail = 0
        self._open_timeout = 0
        self._reject_overload = 0
        self._first_packet_timeout = 0
        self._nonce_replay = 0
        self._acl_reject = 0
        self._qos_reject_conn_rate = 0
        self._qos_reject_max_conns = 0
        self._control_reconnect = 0
        self._reconnect_by_token: Dict[str, int] = {}
        self._open_latency_buckets: Dict[str, int] = {
            'le_50ms': 0,
            'le_100ms': 0,
            'le_300ms': 0,
            'le_1000ms': 0,
            'gt_1000ms': 0,
        }

    def set_allowed_tokens(self, tokens: set[str]) -> None:
        with self._allowed_tokens_lock:
            self._allowed_tokens = set(tokens)
        # drop token mappings not allowed; close orphaned sessions
        orphan_sessions: set[_ControlSession] = set()
        with self._sessions_lock:
            all_sessions = set(self._sessions.values())
            for t in list(self._sessions.keys()):
                if t not in tokens:
                    self._sessions.pop(t, None)
            active_sessions = set(self._sessions.values())
            orphan_sessions = all_sessions - active_sessions
        for sess in orphan_sessions:
            try:
                sess.close('token_removed')
            except Exception:
                pass
        with self._nonce_lock:
            for t in list(self._recent_nonces.keys()):
                if t not in tokens:
                    self._recent_nonces.pop(t, None)
        with self._stats_lock:
            for t in list(self._reconnect_by_token.keys()):
                if t not in tokens:
                    self._reconnect_by_token.pop(t, None)

    def get_session(self, token: str) -> Optional[_ControlSession]:
        with self._sessions_lock:
            s = self._sessions.get(token)
        if s and not s.closed:
            # stale protection
            if (_now() - s.last_seen) > SESSION_STALE:
                s.close('stale')
                with self._sessions_lock:
                    if self._sessions.get(token) is s:
                        self._sessions.pop(token, None)
                return None
            return s
        return None

    def _record_open_result(self, started_at: float, ok: bool, timeout: bool = False) -> None:
        elapsed_ms = int(max(0.0, (_now() - started_at) * 1000.0))
        with self._stats_lock:
            if ok:
                self._open_success += 1
            else:
                self._open_fail += 1
                if timeout:
                    self._open_timeout += 1

            if elapsed_ms <= 50:
                self._open_latency_buckets['le_50ms'] += 1
            elif elapsed_ms <= 100:
                self._open_latency_buckets['le_100ms'] += 1
            elif elapsed_ms <= 300:
                self._open_latency_buckets['le_300ms'] += 1
            elif elapsed_ms <= 1000:
                self._open_latency_buckets['le_1000ms'] += 1
            else:
                self._open_latency_buckets['gt_1000ms'] += 1

    def open_started(self) -> float:
        with self._stats_lock:
            self._open_total += 1
        return _now()

    def open_finished(self, started_at: float, ok: bool, timeout: bool = False) -> None:
        self._record_open_result(started_at, ok=ok, timeout=timeout)

    def acquire_flow_slot(self, proto: str) -> bool:
        if not self._flow_sem.acquire(blocking=False):
            with self._stats_lock:
                self._reject_overload += 1
            return False
        with self._stats_lock:
            self._flow_active += 1
            if self._flow_active > self._flow_peak:
                self._flow_peak = self._flow_active
            if proto == 'udp':
                self._udp_active += 1
                if self._udp_active > self._udp_peak:
                    self._udp_peak = self._udp_active
            else:
                self._tcp_active += 1
                if self._tcp_active > self._tcp_peak:
                    self._tcp_peak = self._tcp_active
        return True

    def release_flow_slot(self, proto: str) -> None:
        with self._stats_lock:
            self._flow_active = max(0, self._flow_active - 1)
            if proto == 'udp':
                self._udp_active = max(0, self._udp_active - 1)
            else:
                self._tcp_active = max(0, self._tcp_active - 1)
        try:
            self._flow_sem.release()
        except Exception:
            pass

    def mark_acl_reject(self) -> None:
        with self._stats_lock:
            self._acl_reject += 1

    def mark_qos_reject(self, kind: str) -> None:
        with self._stats_lock:
            if kind == 'conn_rate':
                self._qos_reject_conn_rate += 1
            elif kind == 'max_conns':
                self._qos_reject_max_conns += 1

    def mark_control_reconnect(self, token: str) -> None:
        tk = str(token or '').strip()
        if not tk:
            return
        with self._stats_lock:
            self._control_reconnect += 1
            self._reconnect_by_token[tk] = int(self._reconnect_by_token.get(tk) or 0) + 1

    def token_reconnects(self, token: str) -> int:
        tk = str(token or '').strip()
        if not tk:
            return 0
        with self._stats_lock:
            return int(self._reconnect_by_token.get(tk) or 0)

    def stats_snapshot(self) -> Dict[str, Any]:
        with self._pending_lock:
            pending = len(self._pending)
        with self._stats_lock:
            return {
                'limits': {
                    'max_accept_workers': int(MAX_ACCEPT_WORKERS),
                    'max_active_flows': int(MAX_ACTIVE_FLOWS),
                },
                'transport': {
                    'socket_rcvbuf': int(SOCKET_RCVBUF),
                    'socket_sndbuf': int(SOCKET_SNDBUF),
                    'tcp_nodelay': bool(TCP_NODELAY),
                    'tcp_relay_chunk': int(TCP_RELAY_CHUNK),
                    'tcp_relay_drain_timeout': float(TCP_RELAY_DRAIN_TIMEOUT),
                    'control_recv_timeout': float(CONTROL_RECV_TIMEOUT),
                    'udp_bridge_stop_wait': float(UDP_BRIDGE_STOP_WAIT),
                    'max_tcp_listener_workers': int(MAX_TCP_LISTENER_WORKERS),
                },
                'accept_workers_active': int(self._accept_active),
                'accept_workers_peak': int(self._accept_peak),
                'flows_active': int(self._flow_active),
                'flows_peak': int(self._flow_peak),
                'tcp_relays_active': int(self._tcp_active),
                'tcp_relays_peak': int(self._tcp_peak),
                'udp_sessions_active': int(self._udp_active),
                'udp_sessions_peak': int(self._udp_peak),
                'open_total': int(self._open_total),
                'open_success': int(self._open_success),
                'open_fail': int(self._open_fail),
                'open_timeout': int(self._open_timeout),
                'open_latency': dict(self._open_latency_buckets),
                'reject_overload': int(self._reject_overload),
                'first_packet_timeout': int(self._first_packet_timeout),
                'nonce_replay_rejected': int(self._nonce_replay),
                'acl_reject': int(self._acl_reject),
                'qos_reject_conn_rate': int(self._qos_reject_conn_rate),
                'qos_reject_max_conns': int(self._qos_reject_max_conns),
                'control_reconnect': int(self._control_reconnect),
                'pending_opens': int(pending),
                'tls_required': bool(self._tls_required),
                'tls_enabled': bool(self._ssl_ctx is not None),
                'startup_error': str(self._startup_error or ''),
            }

    def _remember_nonce(self, token: str, nonce: str) -> bool:
        now = _now()
        cutoff = now - float(NONCE_TTL_SEC)
        with self._nonce_lock:
            by_token = self._recent_nonces.get(token)
            if by_token is None:
                by_token = OrderedDict()
                self._recent_nonces[token] = by_token

            while by_token:
                _nk, seen_at = next(iter(by_token.items()))
                if seen_at >= cutoff:
                    break
                by_token.popitem(last=False)

            if nonce in by_token:
                return False

            by_token[nonce] = now
            while len(by_token) > NONCE_LRU_PER_TOKEN:
                by_token.popitem(last=False)
            return True

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        self._startup_error = ''
        th = threading.Thread(target=self._serve, name=f'intranet-tunnel:{self.port}', daemon=True)
        th.start()
        self._th = th

        jt = threading.Thread(target=self._janitor_loop, name=f'intranet-janitor:{self.port}', daemon=True)
        jt.start()
        self._janitor_th = jt

    def is_running(self) -> bool:
        return bool(self._th and self._th.is_alive() and (not self._startup_error))

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = None
        with self._sessions_lock:
            for s in set(self._sessions.values()):
                s.close('server_stop')
            self._sessions.clear()
        with self._nonce_lock:
            self._recent_nonces.clear()

    def _wrap(self, conn: socket.socket) -> Tuple[Optional[Any], str]:
        # Returns (socket_like, dial_mode)
        if self._ssl_ctx is None:
            if self._tls_required:
                _safe_close(conn)
                return None, 'tls'
            try:
                conn.settimeout(None)
                _set_keepalive(conn)
            except Exception:
                pass
            return conn, 'plain'
        try:
            conn.settimeout(SERVER_TLS_HANDSHAKE_TIMEOUT)
            _set_keepalive(conn)
            ss = self._ssl_ctx.wrap_socket(conn, server_side=True)
            _set_tcp_low_latency(ss)
            ss.settimeout(None)
            return ss, 'tls'
        except socket.timeout as exc:
            _log('accept_wrap_timeout', port=self.port, error=str(exc))
            _safe_close(conn)
            return None, 'tls'
        except Exception as exc:
            _log('accept_wrap_failed', port=self.port, error=str(exc))
            _safe_close(conn)
            return None, 'tls'

    def _serve(self) -> None:
        if self._tls_required and self._ssl_ctx is None:
            self._startup_error = 'tls_context_unavailable'
            _log('server_tls_unavailable', port=int(self.port))
            return
        try:
            s = _bind_socket('', int(self.port), socket.SOCK_STREAM)
            s.listen(TCP_BACKLOG)
        except Exception as exc:
            self._startup_error = f'listen_failed: {exc}'
            _log('server_listen_failed', port=int(self.port), error=str(exc))
            return
        s.settimeout(1.0)
        self._sock = s
        _log('server_listen', port=self.port, tls=bool(self._ssl_ctx is not None))
        while not self._stop.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except Exception:
                continue
            if not self._accept_sem.acquire(blocking=False):
                with self._stats_lock:
                    self._reject_overload += 1
                _safe_close(conn)
                continue
            with self._stats_lock:
                self._accept_active += 1
                if self._accept_active > self._accept_peak:
                    self._accept_peak = self._accept_active
            th = threading.Thread(target=self._handle_conn_guarded, args=(conn, addr), daemon=True)
            th.start()

    def _handle_conn_guarded(self, conn: socket.socket, addr: Any) -> None:
        try:
            self._handle_conn(conn, addr)
        finally:
            with self._stats_lock:
                self._accept_active = max(0, self._accept_active - 1)
            try:
                self._accept_sem.release()
            except Exception:
                pass

    def _handle_conn(self, conn: socket.socket, addr: Any) -> None:
        ss, dial_mode = self._wrap(conn)
        if ss is None:
            return

        # Read first line
        try:
            try:
                ss.settimeout(FIRST_PACKET_TIMEOUT)
            except Exception:
                pass
            line = _recv_line(ss, max_len=FIRST_PACKET_MAX)
            try:
                ss.settimeout(None)
            except Exception:
                pass
            if not line:
                _safe_close(ss)
                return
            # Detect HTTP proxy / wrong port quickly
            if line.startswith('GET ') or line.startswith('POST ') or line.startswith('HTTP/'):
                _log('reject_http', port=self.port, from_addr=str(addr), head=line[:64])
                _safe_close(ss)
                return
            msg = json.loads(line)
        except socket.timeout:
            with self._stats_lock:
                self._first_packet_timeout += 1
            _safe_close(ss)
            return
        except Exception:
            _safe_close(ss)
            return

        mtype = str(msg.get('type') or '')
        if mtype == 'hello':
            self._handle_control(ss, dial_mode, msg, addr)
            return
        if mtype in ('data', 'data_udp', 'data_rev'):
            self._handle_data(ss, msg)
            return
        _safe_close(ss)

    def _token_allowed(self, token: str) -> bool:
        with self._allowed_tokens_lock:
            return token in self._allowed_tokens if self._allowed_tokens else True

    def _send_hello_err(self, ss: Any, err: str) -> None:
        try:
            ss.sendall(_json_line({'type': 'hello_err', 'error': err}))
        except Exception:
            pass

    def _handle_control(self, ss: Any, dial_mode: str, hello: Dict[str, Any], addr: Any) -> None:
        token = str(hello.get('token') or '')
        try:
            node_id = int(hello.get('node_id') or 0)
        except Exception:
            node_id = 0

        if not token or not self._token_allowed(token):
            self._send_hello_err(ss, 'token_invalid')
            _safe_close(ss)
            return

        # HMAC handshake (ver=3). Also accept legacy hello for compatibility.
        legacy = False
        alias_tokens: List[str] = []
        if 'sig' not in hello:
            legacy = True
        else:
            magic = str(hello.get('magic') or '')
            try:
                ver = int(hello.get('ver') or 0)
            except Exception:
                ver = 0
            try:
                ts = int(hello.get('ts') or 0)
            except Exception:
                ts = 0
            nonce = str(hello.get('nonce') or '')
            sig = str(hello.get('sig') or '')

            if magic != INTRANET_MAGIC:
                self._send_hello_err(ss, 'magic_mismatch')
                _safe_close(ss)
                return
            if ver != INTRANET_PROTO_VER:
                self._send_hello_err(ss, 'version_mismatch')
                _safe_close(ss)
                return
            if not nonce or not sig or ts <= 0:
                self._send_hello_err(ss, 'hello_invalid')
                _safe_close(ss)
                return
            if abs(int(_now()) - ts) > TS_SKEW_SEC:
                self._send_hello_err(ss, 'ts_skew')
                _safe_close(ss)
                return
            exp = _hmac_sig(token, node_id, ts, nonce)
            if not hmac.compare_digest(exp, sig):
                self._send_hello_err(ss, 'sig_invalid')
                _safe_close(ss)
                return
            if not self._remember_nonce(token, nonce):
                with self._stats_lock:
                    self._nonce_replay += 1
                self._send_hello_err(ss, 'nonce_replay')
                _safe_close(ss)
                return

            # Optional token aliases allow multiple rules to share one control channel.
            # Each alias must provide its own HMAC signature to prevent token hijacking.
            raw_aliases = hello.get('token_aliases')
            if isinstance(raw_aliases, list):
                seen_aliases: set[str] = {token}
                for row in raw_aliases[:64]:
                    if not isinstance(row, dict):
                        continue
                    alias_token = str(row.get('token') or '').strip()
                    alias_sig = str(row.get('sig') or '').strip()
                    if (not alias_token) or (not alias_sig) or alias_token in seen_aliases:
                        continue
                    if not self._token_allowed(alias_token):
                        continue
                    alias_exp = _hmac_sig(alias_token, node_id, ts, nonce)
                    if not hmac.compare_digest(alias_exp, alias_sig):
                        continue
                    seen_aliases.add(alias_token)
                    alias_tokens.append(alias_token)

        sess = _ControlSession(token=token, node_id=node_id, sock=ss, dial_mode=dial_mode, legacy=legacy)
        bind_tokens = [token] + [x for x in alias_tokens if x != token]
        sess.tokens = set(bind_tokens)
        with self._sessions_lock:
            old_sessions: set[_ControlSession] = set()
            for tk in bind_tokens:
                old = self._sessions.get(tk)
                if old and old is not sess:
                    old_sessions.add(old)
            for old in old_sessions:
                old.close('replaced')
            for tk in bind_tokens:
                if tk in self._sessions and (self._sessions.get(tk) is not sess):
                    self.mark_control_reconnect(tk)
                self._sessions[tk] = sess

        if not sess.send({'type': 'hello_ok', 'ver': INTRANET_PROTO_VER, 'server_ts': int(_now()), 'token_count': len(bind_tokens)}):
            sess.close('hello_ok_send_failed')
            with self._sessions_lock:
                for tk, sv in list(self._sessions.items()):
                    if sv is sess:
                        self._sessions.pop(tk, None)
            return
        _log(
            'control_connected',
            port=self.port,
            token=_mask_token(token),
            node_id=node_id,
            dial_mode=dial_mode,
            legacy=legacy,
            from_addr=str(addr),
            token_count=len(bind_tokens),
        )

        # Keep reading to detect disconnect; also handle ping.
        while not self._stop.is_set() and not sess.closed:
            try:
                line = _recv_line(ss)
                if not line:
                    break
                if line.startswith('GET ') or line.startswith('POST ') or line.startswith('HTTP/'):
                    break
                msg = json.loads(line)
            except Exception:
                break

            t = str(msg.get('type') or '')
            sess.last_seen = _now()

            if t == 'open_rev':
                self._handle_open_reverse(sess, msg)
                continue

            if t == 'ping':
                sess.last_ping_at = sess.last_seen
                # client may report last measured rtt
                try:
                    rtt = msg.get('rtt_ms')
                    if rtt is not None:
                        sess.rtt_ms = int(rtt)
                except Exception:
                    pass
                try:
                    seq = int(msg.get('seq') or 0)
                except Exception:
                    seq = 0
                try:
                    echo_ts = int(msg.get('ts') or 0)
                except Exception:
                    echo_ts = 0
                sess.send({'type': 'pong', 'seq': seq, 'echo_ts': echo_ts, 'server_ts': _now_ms()})

        sess.close('disconnect')
        with self._sessions_lock:
            for tk, sv in list(self._sessions.items()):
                if sv is sess:
                    self._sessions.pop(tk, None)

    def _handle_open_reverse(self, sess: _ControlSession, msg: Dict[str, Any]) -> None:
        conn_id = str(msg.get('conn_id') or '').strip()
        target = str(msg.get('target') or '').strip()
        token = str(msg.get('token') or sess.token).strip() or sess.token
        proto = str(msg.get('proto') or 'tcp').strip().lower() or 'tcp'

        if proto not in ('tcp', 'udp'):
            sess.send({'type': 'open_rev_err', 'conn_id': conn_id, 'error': 'proto_unsupported'})
            return
        if (not conn_id) or (not target):
            sess.send({'type': 'open_rev_err', 'conn_id': conn_id, 'error': 'open_rev_invalid'})
            return
        if token not in getattr(sess, 'tokens', {sess.token}):
            sess.send({'type': 'open_rev_err', 'conn_id': conn_id, 'error': 'token_mismatch'})
            return
        if not self.acquire_flow_slot(proto):
            sess.send({'type': 'open_rev_err', 'conn_id': conn_id, 'error': 'server_overload'})
            return

        opened_at = self.open_started()
        out: Optional[socket.socket] = None
        try:
            host, port = _split_hostport(target)
            if proto == 'udp':
                out, dial_err, _dial_info = _dial_udp_target(host, int(port), 6.0)
            else:
                out, dial_err, _dial_info = _dial_tcp_target(host, int(port), 6.0)
            if not out:
                self.release_flow_slot(proto)
                self.open_finished(opened_at, ok=False)
                sess.send({'type': 'open_rev_err', 'conn_id': conn_id, 'error': str(dial_err or 'dial_failed')})
                return
            out.settimeout(None)
            if proto == 'tcp':
                _set_keepalive(out)
        except Exception as exc:
            _safe_close(out)
            self.release_flow_slot(proto)
            self.open_finished(opened_at, ok=False)
            sess.send({'type': 'open_rev_err', 'conn_id': conn_id, 'error': f'dial_failed: {exc}'})
            return

        key = (token, conn_id)
        with self._pending_lock:
            old = self._pending.pop(key, None)
            self._pending[key] = {
                'created_at': _now(),
                'proto': proto,
                'reverse': True,
                'server_sock': out,
                'flow_proto': proto,
            }
        if isinstance(old, dict):
            _safe_close(old.get('server_sock'))
            if old.get('flow_proto') in ('tcp', 'udp'):
                try:
                    self.release_flow_slot(str(old.get('flow_proto')))
                except Exception:
                    pass

        self.open_finished(opened_at, ok=True)
        if not sess.send({'type': 'open_rev_ok', 'conn_id': conn_id}):
            with self._pending_lock:
                self._pending.pop(key, None)
            _safe_close(out)
            self.release_flow_slot(proto)

    def _handle_data(self, ss: Any, msg: Dict[str, Any]) -> None:
        token = str(msg.get('token') or '')
        conn_id = str(msg.get('conn_id') or '')
        ok = bool(msg.get('ok', True))
        proto = str(msg.get('proto') or 'tcp')

        key = (token, conn_id)
        with self._pending_lock:
            pend = self._pending.get(key)
        if not pend:
            _safe_close(ss)
            return

        # Reverse mode: server side already opened target and waits for client data channel.
        if bool(pend.get('reverse')):
            with self._pending_lock:
                pend2 = self._pending.pop(key, None) or pend
            out = pend2.get('server_sock')
            flow_proto = str(pend2.get('flow_proto') or 'tcp')
            rev_proto = str(pend2.get('proto') or flow_proto or 'tcp').strip().lower() or 'tcp'
            if (not ok) or (out is None):
                _safe_close(out)
                _safe_close(ss)
                if flow_proto in ('tcp', 'udp'):
                    try:
                        self.release_flow_slot(flow_proto)
                    except Exception:
                        pass
                return
            try:
                if rev_proto == 'udp':
                    _relay_udp_stream(ss, out)
                else:
                    _relay_tcp(out, ss)
            finally:
                if flow_proto in ('tcp', 'udp'):
                    try:
                        self.release_flow_slot(flow_proto)
                    except Exception:
                        pass
            return

        pend['data_sock'] = ss
        pend['ok'] = ok
        pend['proto'] = proto
        pend['error'] = str(msg.get('error') or '')
        ev: threading.Event = pend['event']
        ev.set()

    def register_pending(self, token: str, conn_id: str, pend: Dict[str, Any]) -> None:
        with self._pending_lock:
            self._pending[(token, conn_id)] = pend

    def pop_pending(self, token: str, conn_id: str) -> Optional[Dict[str, Any]]:
        with self._pending_lock:
            return self._pending.pop((token, conn_id), None)

    def _janitor_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(2.0)
            now = _now()
            # cleanup stale sessions
            with self._sessions_lock:
                for tok, sess in list(self._sessions.items()):
                    if sess.closed:
                        self._sessions.pop(tok, None)
                        continue
                    if (now - sess.last_seen) > SESSION_STALE:
                        sess.close('stale')
                        self._sessions.pop(tok, None)
            # cleanup pending opens that were never popped (belt & suspenders)
            with self._pending_lock:
                for key, pend in list(self._pending.items()):
                    created = float(pend.get('created_at') or 0.0)
                    if created and (now - created) > max(OPEN_TIMEOUT * 3.0, 30.0):
                        dead = self._pending.pop(key, None)
                        if isinstance(dead, dict):
                            _safe_close(dead.get('server_sock'))
                            flow_proto = str(dead.get('flow_proto') or '')
                            if flow_proto in ('tcp', 'udp'):
                                try:
                                    self.release_flow_slot(flow_proto)
                                except Exception:
                                    pass
            # cleanup replay nonce cache
            cutoff = now - float(NONCE_TTL_SEC)
            with self._nonce_lock:
                for tok, by_token in list(self._recent_nonces.items()):
                    while by_token:
                        _nonce, seen_at = next(iter(by_token.items()))
                        if seen_at >= cutoff:
                            break
                        by_token.popitem(last=False)
                    if not by_token:
                        self._recent_nonces.pop(tok, None)


class _TCPListener:
    def __init__(self, rule: IntranetRule, tunnel: _TunnelServer):
        self.rule = rule
        self.tunnel = tunnel
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._rr = 0
        self._balance_algo, self._balance_weights = _parse_balance(rule.balance, len(rule.remotes or []))
        if len(self._balance_weights) != len(rule.remotes or []):
            self._balance_weights = [1] * len(rule.remotes or [])
        self._wrr_current: List[int] = [0] * len(rule.remotes or [])
        self._latency_ema_ms: Dict[str, float] = {}
        self._jitter_ema_ms: Dict[str, float] = {}
        self._loss_ema: Dict[str, float] = {}
        self._last_latency_sample_ms: Dict[str, float] = {}
        self._latency_samples: Dict[str, int] = {}
        self._route_pick_seq = 0
        self._last_selected_target = ''
        self._last_selected_at = 0.0
        self._rule_lock = threading.Lock()
        self._active_local_conns = 0
        self._active_target_conns: Dict[str, int] = {}
        self._client_sem = threading.BoundedSemaphore(MAX_TCP_LISTENER_WORKERS)

        self._acl_allow_nets = _compile_ip_networks(rule.acl_allow_sources)
        self._acl_deny_nets = _compile_ip_networks(rule.acl_deny_sources)
        self._acl_hours = _compile_hour_windows(rule.acl_allow_hours)
        self._acl_tokens = set(_normalize_str_list(rule.acl_allow_tokens, max_items=64, item_max_len=96))
        self._conn_rate = _ConnRateLimiter(rule.qos_conn_rate) if int(rule.qos_conn_rate or 0) > 0 else None
        self._max_conns = int(rule.qos_max_conns or 0)
        bps = int(max(0, int(rule.qos_bandwidth_kbps or 0)) * 1024 / 8)
        self._bw_limiter = _ByteRateLimiter(bps) if bps > 0 else None

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        th = threading.Thread(target=self._serve, name=f'intranet-tcp:{self.rule.listen}', daemon=True)
        th.start()
        self._th = th

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def _next_rr_index_locked(self, n: int) -> int:
        if n <= 0:
            return 0
        idx = int(self._rr % n)
        self._rr = (self._rr + 1) % n
        return idx

    def _pick_least_conn_index_locked(self, remotes: List[str]) -> int:
        n = len(remotes)
        if n <= 0:
            return 0
        start = self._next_rr_index_locked(n)
        best_idx = 0
        best_load = None
        for ofs in range(n):
            idx = (start + ofs) % n
            target = remotes[idx]
            load = int(max(0, int(self._active_target_conns.get(target, 0))))
            if best_load is None or load < int(best_load):
                best_load = load
                best_idx = idx
        return int(best_idx)

    def _pick_least_latency_index_locked(self, remotes: List[str]) -> int:
        n = len(remotes)
        if n <= 0:
            return 0
        start = self._next_rr_index_locked(n)
        unknown: List[int] = []
        best_idx = -1
        best_score = None
        for ofs in range(n):
            idx = (start + ofs) % n
            target = remotes[idx]
            score = _route_quality_score(
                self._latency_ema_ms.get(target),
                self._jitter_ema_ms.get(target),
                self._loss_ema.get(target),
                int(self._latency_samples.get(target, 0)),
            )
            if score is None:
                unknown.append(idx)
                continue
            if best_score is None or float(score) > float(best_score):
                best_score = score
                best_idx = idx
        self._route_pick_seq = (int(self._route_pick_seq) + 1) % 1000000000
        if unknown and (
            best_idx < 0 or (int(self._route_pick_seq) % max(1, int(LB_ROUTE_EXPLORE_EVERY))) == 0
        ):
            return int(unknown[0])
        if best_idx >= 0:
            return int(best_idx)
        if unknown:
            return int(unknown[0])
        return int(start)

    def _mark_target_active(self, target: str, delta: int) -> None:
        t = str(target or '').strip()
        if not t:
            return
        with self._rule_lock:
            cur = int(self._active_target_conns.get(t, 0)) + int(delta)
            if cur > 0:
                self._active_target_conns[t] = cur
            else:
                self._active_target_conns.pop(t, None)

    def _record_target_open(self, target: str, started_at: float, *, ok: bool, timeout: bool = False) -> None:
        t = str(target or '').strip()
        if not t:
            return
        sample = _latency_sample_ms(started_at, ok=bool(ok), timeout=bool(timeout))
        with self._rule_lock:
            _update_target_quality(
                self._latency_ema_ms,
                self._jitter_ema_ms,
                self._loss_ema,
                self._last_latency_sample_ms,
                self._latency_samples,
                t,
                sample,
                ok=bool(ok),
            )

    def _snapshot_route_info_locked(self) -> Dict[str, Any]:
        remotes = [str(x).strip() for x in (self.rule.remotes or []) if str(x).strip()]
        rows: List[Dict[str, Any]] = []
        for target in remotes:
            lat = self._latency_ema_ms.get(target)
            jit = self._jitter_ema_ms.get(target)
            loss = self._loss_ema.get(target)
            samples = int(self._latency_samples.get(target, 0))
            score = _route_quality_score(lat, jit, loss, samples)
            rows.append(
                {
                    'target': target,
                    'score': (round(float(score), 4) if score is not None else None),
                    'latency_ms': (round(float(lat), 2) if lat is not None else None),
                    'jitter_ms': (round(float(jit), 2) if jit is not None else None),
                    'loss_pct': (round(float(loss) * 100.0, 2) if loss is not None else None),
                    'samples': samples,
                    'active': int(max(0, int(self._active_target_conns.get(target, 0)))),
                    'selected': (target == self._last_selected_target),
                }
            )
        return {
            'proto': 'tcp',
            'algo': str(self._balance_algo or 'roundrobin'),
            'last_selected_target': str(self._last_selected_target or ''),
            'last_selected_at': int(self._last_selected_at) if self._last_selected_at else 0,
            'remotes': rows,
        }

    def snapshot_route_info(self) -> Dict[str, Any]:
        with self._rule_lock:
            return self._snapshot_route_info_locked()

    def _choose_target(self, addr: Any) -> str:
        rs = self.rule.remotes or []
        if not rs:
            return ''
        if len(rs) == 1:
            chosen = str(rs[0])
            with self._rule_lock:
                self._last_selected_target = chosen
                self._last_selected_at = _now()
            return chosen
        with self._rule_lock:
            algo = str(self._balance_algo or 'roundrobin')
            n = len(rs)
            if algo == 'least_conn':
                idx = self._pick_least_conn_index_locked(rs)
            elif algo == 'least_latency':
                idx = self._pick_least_latency_index_locked(rs)
            elif algo in ('iphash', 'consistent_hash'):
                source_key = _addr_source_key(addr)
                if source_key:
                    idx = _pick_consistent_hash_index(rs, source_key, fallback_idx=0)
                else:
                    idx = self._next_rr_index_locked(n)
            elif algo == 'random_weight':
                idx = _pick_weighted_random_index(self._balance_weights)
            elif algo == 'roundrobin':
                if any(int(x) > 1 for x in (self._balance_weights or [])):
                    idx = _pick_weighted_rr_index(self._balance_weights, self._wrr_current)
                else:
                    idx = self._next_rr_index_locked(n)
            else:
                idx = self._next_rr_index_locked(n)
            if idx < 0 or idx >= n:
                idx = self._next_rr_index_locked(n)
            chosen = str(rs[idx])
            self._last_selected_target = chosen
            self._last_selected_at = _now()
            return chosen

    def _serve(self) -> None:
        try:
            host, port = _split_hostport(self.rule.listen)
            s = _bind_socket(host, port, socket.SOCK_STREAM)
            s.listen(TCP_BACKLOG)
        except Exception as exc:
            _log('tcp_listen_failed', listen=self.rule.listen, error=str(exc))
            return
        s.settimeout(1.0)
        self._sock = s
        while not self._stop.is_set():
            try:
                c, addr = s.accept()
                _set_keepalive(c)
            except socket.timeout:
                continue
            except Exception:
                continue
            if not self._client_sem.acquire(blocking=False):
                _log('tcp_listener_overload', listen=self.rule.listen, from_addr=str(addr), max_workers=int(MAX_TCP_LISTENER_WORKERS))
                _safe_close(c)
                continue
            th = threading.Thread(target=self._handle_client_guarded, args=(c, addr), daemon=True)
            th.start()

    def _handle_client_guarded(self, client: socket.socket, addr: Any) -> None:
        try:
            self._handle_client(client, addr)
        finally:
            try:
                self._client_sem.release()
            except Exception:
                pass

    def _allow_client(self, addr: Any) -> Tuple[bool, str]:
        ip_txt = ''
        try:
            if isinstance(addr, tuple) and addr:
                ip_txt = str(addr[0] or '')
        except Exception:
            ip_txt = ''

        if self._acl_tokens and (self.rule.token not in self._acl_tokens):
            return False, 'acl_token'
        if self._acl_hours and (not _match_hour_windows(self._acl_hours)):
            return False, 'acl_time'
        if not _ip_acl_allowed(ip_txt, self._acl_allow_nets, self._acl_deny_nets):
            return False, 'acl_source'
        return True, ''

    def _take_local_conn_slot(self) -> bool:
        if self._max_conns <= 0:
            return True
        with self._rule_lock:
            if self._active_local_conns >= self._max_conns:
                return False
            self._active_local_conns += 1
        return True

    def _release_local_conn_slot(self) -> None:
        if self._max_conns <= 0:
            return
        with self._rule_lock:
            self._active_local_conns = max(0, self._active_local_conns - 1)

    def _handle_client(self, client: socket.socket, addr: Any) -> None:
        local_conn_slot = False
        allowed, deny_reason = self._allow_client(addr)
        if not allowed:
            self.tunnel.mark_acl_reject()
            _log('tcp_acl_reject', listen=self.rule.listen, from_addr=str(addr), reason=deny_reason)
            _safe_close(client)
            return
        if self._conn_rate and (not self._conn_rate.allow()):
            self.tunnel.mark_qos_reject('conn_rate')
            _log('tcp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='conn_rate')
            _safe_close(client)
            return
        if not self._take_local_conn_slot():
            self.tunnel.mark_qos_reject('max_conns')
            _log('tcp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='max_conns')
            _safe_close(client)
            return
        local_conn_slot = True

        if not self.tunnel.acquire_flow_slot('tcp'):
            _safe_close(client)
            self._release_local_conn_slot()
            return

        opened_at = self.tunnel.open_started()
        open_recorded = False
        target = ''
        target_marked = False
        token = self.rule.token
        try:
            sess = self.tunnel.get_session(token)
            if not sess:
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                _safe_close(client)
                return
            target = self._choose_target(addr)
            if not target:
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                _safe_close(client)
                return
            self._mark_target_active(target, +1)
            target_marked = True

            conn_id = uuid.uuid4().hex
            ev = threading.Event()
            pend = {'event': ev, 'client_sock': client, 'proto': 'tcp', 'created_at': _now()}
            self.tunnel.register_pending(token, conn_id, pend)

            # ask B to open
            if not sess.send({'type': 'open', 'conn_id': conn_id, 'proto': 'tcp', 'target': target, 'token': token}):
                self.tunnel.pop_pending(token, conn_id)
                self.tunnel.open_finished(opened_at, ok=False)
                self._record_target_open(target, opened_at, ok=False)
                open_recorded = True
                _safe_close(client)
                return

            if not ev.wait(timeout=OPEN_TIMEOUT):
                self.tunnel.pop_pending(token, conn_id)
                self.tunnel.open_finished(opened_at, ok=False, timeout=True)
                self._record_target_open(target, opened_at, ok=False, timeout=True)
                open_recorded = True
                _safe_close(client)
                return

            pend2 = self.tunnel.pop_pending(token, conn_id) or pend
            data_sock = pend2.get('data_sock')
            ok = bool(pend2.get('ok', True))
            if not ok or not data_sock:
                self.tunnel.open_finished(opened_at, ok=False)
                self._record_target_open(target, opened_at, ok=False)
                open_recorded = True
                _safe_close(client)
                _safe_close(data_sock)
                return

            self.tunnel.open_finished(opened_at, ok=True)
            self._record_target_open(target, opened_at, ok=True)
            open_recorded = True
            _relay_tcp(client, data_sock, limiter=self._bw_limiter)
        finally:
            if not open_recorded:
                self.tunnel.open_finished(opened_at, ok=False)
                self._record_target_open(target, opened_at, ok=False)
            self.tunnel.release_flow_slot('tcp')
            if local_conn_slot:
                self._release_local_conn_slot()
            if target_marked:
                self._mark_target_active(target, -1)


class _NoopTunnelServer:
    def mark_acl_reject(self) -> None:
        return

    def mark_qos_reject(self, _kind: str) -> None:
        return

    def acquire_flow_slot(self, _proto: str) -> bool:
        return True

    def release_flow_slot(self, _proto: str) -> None:
        return

    def open_started(self) -> float:
        return _now()

    def open_finished(self, _started_at: float, ok: bool, timeout: bool = False) -> None:
        return


_NOOP_TUNNEL_SERVER = _NoopTunnelServer()


class _ClientTCPListener(_TCPListener):
    """Client-side listener for reverse tunnel mode.

    Local listener accepts traffic, asks peer server to open target on server side,
    then bridges payload over `data_rev` channel.
    """

    def __init__(self, rule: IntranetRule, client: _TunnelClient):
        super().__init__(rule=rule, tunnel=_NOOP_TUNNEL_SERVER)  # type: ignore[arg-type]
        self.client = client

    def _handle_client(self, client_sock: socket.socket, addr: Any) -> None:
        local_conn_slot = False
        allowed, deny_reason = self._allow_client(addr)
        if not allowed:
            _log('reverse_tcp_acl_reject', listen=self.rule.listen, from_addr=str(addr), reason=deny_reason)
            _safe_close(client_sock)
            return
        if self._conn_rate and (not self._conn_rate.allow()):
            _log('reverse_tcp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='conn_rate')
            _safe_close(client_sock)
            return
        if not self._take_local_conn_slot():
            _log('reverse_tcp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='max_conns')
            _safe_close(client_sock)
            return
        local_conn_slot = True

        opened_at = _now()
        open_recorded = False
        target = ''
        target_marked = False
        token = self.rule.token
        try:
            target = self._choose_target(addr)
            if not target:
                self._record_target_open(target, opened_at, ok=False)
                open_recorded = True
                _safe_close(client_sock)
                return
            self._mark_target_active(target, +1)
            target_marked = True

            data_sock, err = self.client.open_reverse_stream(target, token)
            if not data_sock:
                is_timeout = str(err or '').startswith('open_rev_timeout')
                self._record_target_open(target, opened_at, ok=False, timeout=is_timeout)
                open_recorded = True
                _safe_close(client_sock)
                return

            self._record_target_open(target, opened_at, ok=True)
            open_recorded = True
            _relay_tcp(client_sock, data_sock, limiter=self._bw_limiter)
        finally:
            if (not open_recorded) and target:
                self._record_target_open(target, opened_at, ok=False)
            if local_conn_slot:
                self._release_local_conn_slot()
            if target_marked:
                self._mark_target_active(target, -1)


class _ClientUDPSession:
    def __init__(
        self,
        udp_sock: socket.socket,
        client_addr: Tuple[str, int],
        client: _TunnelClient,
        target: str,
        token: str,
        limiter: Optional[_ByteRateLimiter] = None,
    ):
        self.udp_sock = udp_sock
        self.client_addr = client_addr
        self.client = client
        self.target = target
        self.token = token
        self.data_sock: Optional[Any] = None
        self.ok = False
        self.last_seen = _now()
        self._send_lock = threading.Lock()
        self._rx_th: Optional[threading.Thread] = None
        self._limiter = limiter

    def open(self) -> bool:
        ds, err = self.client.open_reverse_stream(self.target, self.token, proto='udp')
        if not ds:
            return False
        self.data_sock = ds
        self.ok = True
        th = threading.Thread(target=self._rx_loop, name='intranet-reverse-udp-rx', daemon=True)
        th.start()
        self._rx_th = th
        return True

    def send_datagram(self, payload: bytes) -> None:
        self.last_seen = _now()
        if not self.data_sock:
            return
        if len(payload) > MAX_FRAME:
            payload = payload[:MAX_FRAME]
        frame = struct.pack('!I', len(payload)) + payload
        try:
            with self._send_lock:
                if self._limiter is not None:
                    self._limiter.consume(len(frame))
                self.data_sock.sendall(frame)
        except Exception:
            self.close()

    def _rx_loop(self) -> None:
        ds = self.data_sock
        if not ds:
            return
        try:
            while True:
                hdr = _recv_exact(ds, 4)
                if not hdr:
                    break
                (n,) = struct.unpack('!I', hdr)
                if n <= 0 or n > MAX_FRAME:
                    break
                data = _recv_exact(ds, n)
                if not data:
                    break
                if self._limiter is not None:
                    self._limiter.consume(len(data))
                self.udp_sock.sendto(data, self.client_addr)
        except Exception:
            pass
        _safe_close(ds)
        self.data_sock = None
        self.ok = False

    def close(self) -> None:
        _safe_close(self.data_sock)
        self.data_sock = None
        self.ok = False


class _UDPSession:
    def __init__(
        self,
        udp_sock: socket.socket,
        client_addr: Tuple[str, int],
        token: str,
        tunnel: _TunnelServer,
        target: str,
        limiter: Optional[_ByteRateLimiter] = None,
    ):
        self.udp_sock = udp_sock
        self.client_addr = client_addr
        self.token = token
        self.tunnel = tunnel
        self.target = target
        self.conn_id = uuid.uuid4().hex
        self.data_sock: Optional[Any] = None
        self.ok = False
        self.last_seen = _now()
        self._send_lock = threading.Lock()
        self._rx_th: Optional[threading.Thread] = None
        self._flow_slot_acquired = False
        self._limiter = limiter

    def open(self) -> bool:
        if not self.tunnel.acquire_flow_slot('udp'):
            return False
        self._flow_slot_acquired = True
        opened_at = self.tunnel.open_started()
        open_recorded = False
        try:
            sess = self.tunnel.get_session(self.token)
            if not sess:
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                self.close()
                return False
            ev = threading.Event()
            pend = {'event': ev, 'proto': 'udp', 'created_at': _now()}
            self.tunnel.register_pending(self.token, self.conn_id, pend)
            if not sess.send({'type': 'open', 'conn_id': self.conn_id, 'proto': 'udp', 'target': self.target, 'token': self.token}):
                self.tunnel.pop_pending(self.token, self.conn_id)
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                self.close()
                return False
            if not ev.wait(timeout=OPEN_TIMEOUT):
                self.tunnel.pop_pending(self.token, self.conn_id)
                self.tunnel.open_finished(opened_at, ok=False, timeout=True)
                open_recorded = True
                self.close()
                return False
            pend2 = self.tunnel.pop_pending(self.token, self.conn_id) or pend
            self.data_sock = pend2.get('data_sock')
            self.ok = bool(pend2.get('ok', True)) and self.data_sock is not None
            if not self.ok:
                self.tunnel.open_finished(opened_at, ok=False)
                open_recorded = True
                _safe_close(self.data_sock)
                self.data_sock = None
                self.close()
                return False

            self.tunnel.open_finished(opened_at, ok=True)
            open_recorded = True
            th = threading.Thread(target=self._rx_loop, name='intranet-udp-rx', daemon=True)
            th.start()
            self._rx_th = th
            return True
        except Exception:
            if not open_recorded:
                self.tunnel.open_finished(opened_at, ok=False)
            self.close()
            return False

    def send_datagram(self, payload: bytes) -> None:
        self.last_seen = _now()
        if not self.data_sock:
            return
        if len(payload) > MAX_FRAME:
            payload = payload[:MAX_FRAME]
        frame = struct.pack('!I', len(payload)) + payload
        try:
            with self._send_lock:
                if self._limiter is not None:
                    self._limiter.consume(len(frame))
                self.data_sock.sendall(frame)
        except Exception:
            self.close()

    def _rx_loop(self) -> None:
        ds = self.data_sock
        if not ds:
            return
        try:
            while True:
                hdr = _recv_exact(ds, 4)
                if not hdr:
                    break
                (n,) = struct.unpack('!I', hdr)
                if n <= 0 or n > MAX_FRAME:
                    break
                data = _recv_exact(ds, n)
                if not data:
                    break
                if self._limiter is not None:
                    self._limiter.consume(len(data))
                self.udp_sock.sendto(data, self.client_addr)
        except Exception:
            pass
        _safe_close(ds)
        self.data_sock = None
        self.ok = False
        self._release_flow_slot()

    def close(self) -> None:
        _safe_close(self.data_sock)
        self.data_sock = None
        self.ok = False
        self._release_flow_slot()

    def _release_flow_slot(self) -> None:
        if not self._flow_slot_acquired:
            return
        self._flow_slot_acquired = False
        self.tunnel.release_flow_slot('udp')


class _UDPListener:
    def __init__(self, rule: IntranetRule, tunnel: _TunnelServer):
        self.rule = rule
        self.tunnel = tunnel
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._sessions: Dict[Tuple[str, int], _UDPSession] = {}
        self._lock = threading.Lock()
        self._rr = 0
        self._balance_algo, self._balance_weights = _parse_balance(rule.balance, len(rule.remotes or []))
        if len(self._balance_weights) != len(rule.remotes or []):
            self._balance_weights = [1] * len(rule.remotes or [])
        self._wrr_current: List[int] = [0] * len(rule.remotes or [])
        self._latency_ema_ms: Dict[str, float] = {}
        self._jitter_ema_ms: Dict[str, float] = {}
        self._loss_ema: Dict[str, float] = {}
        self._last_latency_sample_ms: Dict[str, float] = {}
        self._latency_samples: Dict[str, int] = {}
        self._route_pick_seq = 0
        self._last_selected_target = ''
        self._last_selected_at = 0.0
        self._acl_allow_nets = _compile_ip_networks(rule.acl_allow_sources)
        self._acl_deny_nets = _compile_ip_networks(rule.acl_deny_sources)
        self._acl_hours = _compile_hour_windows(rule.acl_allow_hours)
        self._acl_tokens = set(_normalize_str_list(rule.acl_allow_tokens, max_items=64, item_max_len=96))
        self._conn_rate = _ConnRateLimiter(rule.qos_conn_rate) if int(rule.qos_conn_rate or 0) > 0 else None
        self._max_conns = int(rule.qos_max_conns or 0)
        bps = int(max(0, int(rule.qos_bandwidth_kbps or 0)) * 1024 / 8)
        self._bw_limiter = _ByteRateLimiter(bps) if bps > 0 else None

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        th = threading.Thread(target=self._serve, name=f'intranet-udp:{self.rule.listen}', daemon=True)
        th.start()
        self._th = th

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        with self._lock:
            for s in self._sessions.values():
                s.close()
            self._sessions.clear()

    def _next_rr_index_locked(self, n: int) -> int:
        if n <= 0:
            return 0
        idx = int(self._rr % n)
        self._rr = (self._rr + 1) % n
        return idx

    def _active_session_counts_locked(self, remotes: List[str]) -> Dict[str, int]:
        counts: Dict[str, int] = {str(r): 0 for r in remotes}
        for sess in self._sessions.values():
            t = str(getattr(sess, 'target', '') or '').strip()
            if not t:
                continue
            if not bool(getattr(sess, 'ok', False)):
                continue
            counts[t] = int(counts.get(t, 0)) + 1
        return counts

    def _pick_least_conn_index_locked(self, remotes: List[str]) -> int:
        n = len(remotes)
        if n <= 0:
            return 0
        counts = self._active_session_counts_locked(remotes)
        start = self._next_rr_index_locked(n)
        best_idx = 0
        best_load = None
        for ofs in range(n):
            idx = (start + ofs) % n
            target = remotes[idx]
            load = int(max(0, int(counts.get(target, 0))))
            if best_load is None or load < int(best_load):
                best_load = load
                best_idx = idx
        return int(best_idx)

    def _pick_least_latency_index_locked(self, remotes: List[str]) -> int:
        n = len(remotes)
        if n <= 0:
            return 0
        start = self._next_rr_index_locked(n)
        unknown: List[int] = []
        best_idx = -1
        best_score = None
        for ofs in range(n):
            idx = (start + ofs) % n
            target = remotes[idx]
            score = _route_quality_score(
                self._latency_ema_ms.get(target),
                self._jitter_ema_ms.get(target),
                self._loss_ema.get(target),
                int(self._latency_samples.get(target, 0)),
            )
            if score is None:
                unknown.append(idx)
                continue
            if best_score is None or float(score) > float(best_score):
                best_score = score
                best_idx = idx
        self._route_pick_seq = (int(self._route_pick_seq) + 1) % 1000000000
        if unknown and (
            best_idx < 0 or (int(self._route_pick_seq) % max(1, int(LB_ROUTE_EXPLORE_EVERY))) == 0
        ):
            return int(unknown[0])
        if best_idx >= 0:
            return int(best_idx)
        if unknown:
            return int(unknown[0])
        return int(start)

    def _record_target_open(self, target: str, started_at: float, *, ok: bool, timeout: bool = False) -> None:
        t = str(target or '').strip()
        if not t:
            return
        sample = _latency_sample_ms(started_at, ok=bool(ok), timeout=bool(timeout))
        with self._lock:
            _update_target_quality(
                self._latency_ema_ms,
                self._jitter_ema_ms,
                self._loss_ema,
                self._last_latency_sample_ms,
                self._latency_samples,
                t,
                sample,
                ok=bool(ok),
            )

    def _snapshot_route_info_locked(self) -> Dict[str, Any]:
        remotes = [str(x).strip() for x in (self.rule.remotes or []) if str(x).strip()]
        counts = self._active_session_counts_locked(remotes)
        rows: List[Dict[str, Any]] = []
        for target in remotes:
            lat = self._latency_ema_ms.get(target)
            jit = self._jitter_ema_ms.get(target)
            loss = self._loss_ema.get(target)
            samples = int(self._latency_samples.get(target, 0))
            score = _route_quality_score(lat, jit, loss, samples)
            rows.append(
                {
                    'target': target,
                    'score': (round(float(score), 4) if score is not None else None),
                    'latency_ms': (round(float(lat), 2) if lat is not None else None),
                    'jitter_ms': (round(float(jit), 2) if jit is not None else None),
                    'loss_pct': (round(float(loss) * 100.0, 2) if loss is not None else None),
                    'samples': samples,
                    'active': int(max(0, int(counts.get(target, 0)))),
                    'selected': (target == self._last_selected_target),
                }
            )
        return {
            'proto': 'udp',
            'algo': str(self._balance_algo or 'roundrobin'),
            'last_selected_target': str(self._last_selected_target or ''),
            'last_selected_at': int(self._last_selected_at) if self._last_selected_at else 0,
            'remotes': rows,
        }

    def snapshot_route_info(self) -> Dict[str, Any]:
        with self._lock:
            return self._snapshot_route_info_locked()

    def _choose_target(self, addr: Any) -> str:
        rs = self.rule.remotes or []
        if not rs:
            return ''
        if len(rs) == 1:
            chosen = str(rs[0])
            with self._lock:
                self._last_selected_target = chosen
                self._last_selected_at = _now()
            return chosen
        with self._lock:
            algo = str(self._balance_algo or 'roundrobin')
            n = len(rs)
            if algo == 'least_conn':
                idx = self._pick_least_conn_index_locked(rs)
            elif algo == 'least_latency':
                idx = self._pick_least_latency_index_locked(rs)
            elif algo in ('iphash', 'consistent_hash'):
                source_key = _addr_source_key(addr)
                if source_key:
                    idx = _pick_consistent_hash_index(rs, source_key, fallback_idx=0)
                else:
                    idx = self._next_rr_index_locked(n)
            elif algo == 'random_weight':
                idx = _pick_weighted_random_index(self._balance_weights)
            elif algo == 'roundrobin':
                if any(int(x) > 1 for x in (self._balance_weights or [])):
                    idx = _pick_weighted_rr_index(self._balance_weights, self._wrr_current)
                else:
                    idx = self._next_rr_index_locked(n)
            else:
                idx = self._next_rr_index_locked(n)
            if idx < 0 or idx >= n:
                idx = self._next_rr_index_locked(n)
            chosen = str(rs[idx])
            self._last_selected_target = chosen
            self._last_selected_at = _now()
            return chosen

    def _allow_client(self, addr: Any) -> Tuple[bool, str]:
        ip_txt = ''
        try:
            if isinstance(addr, tuple) and addr:
                ip_txt = str(addr[0] or '')
        except Exception:
            ip_txt = ''

        if self._acl_tokens and (self.rule.token not in self._acl_tokens):
            return False, 'acl_token'
        if self._acl_hours and (not _match_hour_windows(self._acl_hours)):
            return False, 'acl_time'
        if not _ip_acl_allowed(ip_txt, self._acl_allow_nets, self._acl_deny_nets):
            return False, 'acl_source'
        return True, ''

    def _serve(self) -> None:
        try:
            host, port = _split_hostport(self.rule.listen)
            s = _bind_socket(host, port, socket.SOCK_DGRAM)
        except Exception as exc:
            _log('udp_listen_failed', listen=self.rule.listen, error=str(exc))
            return
        s.settimeout(1.0)
        self._sock = s

        threading.Thread(target=self._cleanup_loop, daemon=True).start()

        while not self._stop.is_set():
            try:
                data, addr = s.recvfrom(MAX_FRAME)
            except socket.timeout:
                continue
            except Exception:
                continue

            if not data:
                continue
            allowed, deny_reason = self._allow_client(addr)
            if not allowed:
                self.tunnel.mark_acl_reject()
                _log('udp_acl_reject', listen=self.rule.listen, from_addr=str(addr), reason=deny_reason)
                continue
            with self._lock:
                sess = self._sessions.get(addr)
            if not sess or not sess.ok or sess.data_sock is None:
                if self._conn_rate and (not self._conn_rate.allow()):
                    self.tunnel.mark_qos_reject('conn_rate')
                    _log('udp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='conn_rate')
                    continue
                if self._max_conns > 0:
                    with self._lock:
                        cur_sessions = len(self._sessions)
                    if cur_sessions >= self._max_conns:
                        self.tunnel.mark_qos_reject('max_conns')
                        _log('udp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='max_conns')
                        continue
                target = self._choose_target(addr)
                if not target:
                    continue
                old_sess = sess
                sess = _UDPSession(
                    udp_sock=s,
                    client_addr=addr,
                    token=self.rule.token,
                    tunnel=self.tunnel,
                    target=target,
                    limiter=self._bw_limiter,
                )
                opened_at = _now()
                if not sess.open():
                    is_timeout = (_now() - opened_at) >= max(0.5, float(OPEN_TIMEOUT) - 0.05)
                    self._record_target_open(target, opened_at, ok=False, timeout=is_timeout)
                    if old_sess:
                        old_sess.close()
                    continue
                self._record_target_open(target, opened_at, ok=True)
                with self._lock:
                    if old_sess:
                        old_sess.close()
                    self._sessions[addr] = sess
            sess.send_datagram(data)

    def _cleanup_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(2.0)
            now = _now()
            dead: List[Tuple[str, int]] = []
            with self._lock:
                for addr, sess in self._sessions.items():
                    if (now - sess.last_seen) > UDP_SESSION_TTL:
                        dead.append(addr)
                for addr in dead:
                    s = self._sessions.pop(addr, None)
                    if s:
                        s.close()


class _ClientUDPListener(_UDPListener):
    """Client-side UDP listener for reverse tunnel mode."""

    def __init__(self, rule: IntranetRule, client: "_TunnelClient"):
        super().__init__(rule=rule, tunnel=_NOOP_TUNNEL_SERVER)  # type: ignore[arg-type]
        self.client = client

    def _serve(self) -> None:
        try:
            host, port = _split_hostport(self.rule.listen)
            s = _bind_socket(host, port, socket.SOCK_DGRAM)
        except Exception as exc:
            _log('reverse_udp_listen_failed', listen=self.rule.listen, error=str(exc))
            return
        s.settimeout(1.0)
        self._sock = s

        threading.Thread(target=self._cleanup_loop, daemon=True).start()

        while not self._stop.is_set():
            try:
                data, addr = s.recvfrom(MAX_FRAME)
            except socket.timeout:
                continue
            except Exception:
                continue

            if not data:
                continue
            allowed, deny_reason = self._allow_client(addr)
            if not allowed:
                _log('reverse_udp_acl_reject', listen=self.rule.listen, from_addr=str(addr), reason=deny_reason)
                continue
            with self._lock:
                sess = self._sessions.get(addr)
            if not sess or not sess.ok or sess.data_sock is None:
                if self._conn_rate and (not self._conn_rate.allow()):
                    _log('reverse_udp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='conn_rate')
                    continue
                if self._max_conns > 0:
                    with self._lock:
                        cur_sessions = len(self._sessions)
                    if cur_sessions >= self._max_conns:
                        _log('reverse_udp_qos_reject', listen=self.rule.listen, from_addr=str(addr), reason='max_conns')
                        continue
                target = self._choose_target(addr)
                if not target:
                    continue
                old_sess = sess
                sess = _ClientUDPSession(
                    udp_sock=s,
                    client_addr=addr,
                    client=self.client,
                    target=target,
                    token=self.rule.token,
                    limiter=self._bw_limiter,
                )
                opened_at = _now()
                if not sess.open():
                    is_timeout = (_now() - opened_at) >= max(0.5, float(OPEN_TIMEOUT) - 0.05)
                    self._record_target_open(target, opened_at, ok=False, timeout=is_timeout)
                    if old_sess:
                        old_sess.close()
                    continue
                self._record_target_open(target, opened_at, ok=True)
                with self._lock:
                    if old_sess:
                        old_sess.close()
                    self._sessions[addr] = sess
            sess.send_datagram(data)


@dataclass
class _ClientState:
    peer_host: str
    peer_port: int
    token: str
    node_id: int
    connected: bool = False
    dial_mode: str = ''
    last_attempt_at: float = 0.0
    last_connected_at: float = 0.0
    last_hello_ok_at: float = 0.0
    last_pong_at: float = 0.0
    rtt_ms: Optional[int] = None
    handshake_ms: Optional[int] = None
    last_error: str = ''
    reconnects: int = 0
    ping_sent: int = 0
    pong_recv: int = 0
    loss_pct: float = 0.0
    jitter_ms: int = 0
    he_enabled: bool = False
    he_mode: str = ''
    he_family: str = ''
    he_addr: str = ''
    he_attempts: int = 0
    he_last_at: float = 0.0


class _TunnelClient:
    """B-side client maintaining control connection to A, and opening data connections on demand."""

    def __init__(
        self,
        peer_host: str,
        peer_port: int,
        token: str,
        tokens: Optional[List[str]],
        node_id: int,
        server_cert_pem: str = '',
        tls_verify: bool = False,
    ):
        self.peer_host = peer_host
        self.peer_port = int(peer_port)
        uniq_tokens: List[str] = []
        seen_tokens: set[str] = set()
        for tk in [token] + (tokens or []):
            st = str(tk or '').strip()
            if (not st) or (st in seen_tokens):
                continue
            seen_tokens.add(st)
            uniq_tokens.append(st)
        if not uniq_tokens:
            uniq_tokens = [str(token or '').strip()]
        self.tokens = uniq_tokens
        self._token_set = set(uniq_tokens)
        self.token = uniq_tokens[0]
        self.node_id = int(node_id)
        self.server_cert_pem = server_cert_pem or ''
        self.tls_verify = bool(tls_verify)
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None

        self._state_lock = threading.Lock()
        self._state = _ClientState(peer_host=self.peer_host, peer_port=self.peer_port, token=self.token, node_id=self.node_id)
        self._tls_ctx: Optional[ssl.SSLContext] = None
        self._tls_ctx_err = ''
        self._open_sem = threading.BoundedSemaphore(MAX_CLIENT_OPEN_WORKERS)
        self._ctrl_lock = threading.Lock()
        self._ctrl_sock: Optional[Any] = None
        self._rev_open_lock = threading.Lock()
        self._rev_open_wait: Dict[str, Dict[str, Any]] = {}
        self._had_connected = False
        self._reconnects = 0
        self._build_tls_context()

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        th = threading.Thread(target=self._loop, name=f'intranet-client:{self.peer_host}:{self.peer_port}', daemon=True)
        th.start()
        self._th = th

    def stop(self) -> None:
        self._stop.set()
        ss: Optional[Any] = None
        with self._ctrl_lock:
            ss = self._ctrl_sock
            self._ctrl_sock = None
        self._fail_rev_open_waiters('client_stopped')
        _safe_close(ss)

    def get_state(self) -> Dict[str, Any]:
        with self._state_lock:
            st = self._state
            return {
                'peer_host': st.peer_host,
                'peer_port': st.peer_port,
                'token': _mask_token(st.token),
                'token_count': len(self.tokens),
                'connected': st.connected,
                'dial_mode': st.dial_mode,
                'last_attempt_at': int(st.last_attempt_at) if st.last_attempt_at else 0,
                'last_connected_at': int(st.last_connected_at) if st.last_connected_at else 0,
                'last_hello_ok_at': int(st.last_hello_ok_at) if st.last_hello_ok_at else 0,
                'last_pong_at': int(st.last_pong_at) if st.last_pong_at else 0,
                'rtt_ms': st.rtt_ms,
                'handshake_ms': st.handshake_ms,
                'last_error': st.last_error,
                'tls_verify': bool(self.tls_verify),
                'reconnects': int(st.reconnects),
                'ping_sent': int(st.ping_sent),
                'pong_recv': int(st.pong_recv),
                'loss_pct': float(st.loss_pct),
                'jitter_ms': int(st.jitter_ms),
                'he_enabled': bool(st.he_enabled),
                'he_mode': str(st.he_mode or ''),
                'he_family': str(st.he_family or ''),
                'he_addr': str(st.he_addr or ''),
                'he_attempts': int(st.he_attempts),
                'he_last_at': int(st.he_last_at) if st.he_last_at else 0,
            }

    def _set_state(self, **kwargs: Any) -> None:
        with self._state_lock:
            for k, v in kwargs.items():
                if hasattr(self._state, k):
                    setattr(self._state, k, v)

    def _set_happy_eyeballs_state(self, info: Dict[str, Any]) -> None:
        if not isinstance(info, dict):
            return
        try:
            attempts = int(info.get('attempts') or 0)
        except Exception:
            attempts = 0
        self._set_state(
            he_enabled=bool(info.get('happy_eyeballs_enabled', DIAL_HAPPY_EYEBALLS)),
            he_mode=str(info.get('race_mode') or ('happy_eyeballs' if DIAL_HAPPY_EYEBALLS else 'sequential')),
            he_family=str(info.get('winner_family') or ''),
            he_addr=str(info.get('winner_addr') or '')[:160],
            he_attempts=max(0, attempts),
            he_last_at=_now(),
        )

    def matches_config(self, server_cert_pem: str, tls_verify: bool, tokens: Optional[List[str]] = None) -> bool:
        cfg_tokens = _normalize_str_list(tokens or [], max_items=256, item_max_len=128)
        if not cfg_tokens:
            cfg_tokens = [self.token]
        return (
            (self.server_cert_pem == (server_cert_pem or ''))
            and (self.tls_verify == bool(tls_verify))
            and (set(cfg_tokens) == self._token_set)
        )

    def owns_token(self, token: str) -> bool:
        return str(token or '').strip() in self._token_set

    def _set_ctrl_sock(self, ss: Optional[Any]) -> None:
        with self._ctrl_lock:
            self._ctrl_sock = ss

    def _send_control(self, msg: Dict[str, Any]) -> bool:
        with self._ctrl_lock:
            ss = self._ctrl_sock
            if ss is None:
                return False
            try:
                ss.sendall(_json_line(msg))
                return True
            except Exception:
                return False

    def _fail_rev_open_waiters(self, error: str) -> None:
        rows: List[Dict[str, Any]] = []
        with self._rev_open_lock:
            if self._rev_open_wait:
                rows = list(self._rev_open_wait.values())
                self._rev_open_wait.clear()
        for row in rows:
            try:
                row['ok'] = False
                row['error'] = str(error or 'control_closed')
                ev = row.get('event')
                if isinstance(ev, threading.Event):
                    ev.set()
            except Exception:
                pass

    def _request_open_reverse(self, target: str, req_token: str, *, proto: str = 'tcp') -> Tuple[str, str]:
        tgt = str(target or '').strip()
        tok = str(req_token or '').strip() or self.token
        p = str(proto or 'tcp').strip().lower() or 'tcp'
        if not tgt:
            return '', 'target_empty'
        if not tok:
            return '', 'token_empty'
        if not self.owns_token(tok):
            return '', 'token_invalid'
        if p not in ('tcp', 'udp'):
            return '', 'proto_unsupported'
        conn_id = uuid.uuid4().hex
        ev = threading.Event()
        row: Dict[str, Any] = {'event': ev, 'ok': None, 'error': ''}
        with self._rev_open_lock:
            self._rev_open_wait[conn_id] = row

        sent = self._send_control({'type': 'open_rev', 'conn_id': conn_id, 'proto': p, 'target': tgt, 'token': tok})
        if not sent:
            with self._rev_open_lock:
                self._rev_open_wait.pop(conn_id, None)
            return '', 'control_send_failed'

        if not ev.wait(timeout=OPEN_TIMEOUT):
            with self._rev_open_lock:
                self._rev_open_wait.pop(conn_id, None)
            return '', 'open_rev_timeout'

        with self._rev_open_lock:
            out = self._rev_open_wait.pop(conn_id, None)
        if not isinstance(out, dict):
            return '', 'open_rev_state_missing'
        if not bool(out.get('ok')):
            return '', str(out.get('error') or 'open_rev_failed')
        return conn_id, ''

    def open_reverse_stream(self, target: str, req_token: str, *, proto: str = 'tcp') -> Tuple[Optional[Any], str]:
        p = str(proto or 'tcp').strip().lower() or 'tcp'
        token = str(req_token or '').strip() or self.token
        conn_id, err = self._request_open_reverse(target, token, proto=p)
        if not conn_id:
            return None, err

        ds, derr = self._open_data()
        if not ds:
            return None, derr
        try:
            ds.sendall(_json_line({'type': 'data_rev', 'proto': p, 'token': token, 'conn_id': conn_id, 'ok': True}))
        except Exception as exc:
            _safe_close(ds)
            return None, f'data_rev_send_failed: {exc}'
        return ds, ''

    def _build_tls_context(self) -> None:
        try:
            self._tls_ctx = _mk_client_ssl_context(
                self.server_cert_pem or None,
                require_verify=bool(self.tls_verify),
            )
            self._tls_ctx_err = ''
        except Exception as exc:
            self._tls_ctx = None
            self._tls_ctx_err = f'tls_context_failed: {exc}'

    def _dial(self) -> Tuple[Optional[Any], str, str]:
        """Dial A-side tunnel port.

        Use TLS by default. Plaintext fallback is disabled unless explicitly enabled
        via REALM_INTRANET_ALLOW_PLAINTEXT=1 for break-glass compatibility.

        Returns: (socket_like, dial_mode, error)
        """
        raw, dial_err, dial_info = _dial_tcp_target(self.peer_host, self.peer_port, DIAL_CONNECT_TIMEOUT)
        self._set_happy_eyeballs_state(dial_info)
        if not raw:
            return None, '', f'dial_failed: {dial_err}'
        try:
            raw.settimeout(DIAL_TLS_TIMEOUT)
            _set_keepalive(raw)
        except Exception as exc:
            _safe_close(raw)
            return None, '', f'dial_failed: {exc}'

        if self._tls_ctx is None:
            _safe_close(raw)
            return None, '', (self._tls_ctx_err or 'tls_context_unavailable')

        # TLS first
        try:
            ctx = self._tls_ctx
            ss = ctx.wrap_socket(raw, server_hostname=None)
            _set_tcp_low_latency(ss)
            ss.settimeout(None)
            return ss, 'tls', ''
        except socket.timeout as exc:
            _safe_close(raw)
            return None, '', f'dial_tls_timeout: {exc}'
        except ssl.SSLCertVerificationError as exc:
            _safe_close(raw)
            return None, '', f'tls_verify_failed: {exc}'
        except ssl.SSLError as exc:
            msg = str(exc).upper()
            # Only fall back when TLS is not required and error indicates server is plaintext/HTTP.
            if (not self.server_cert_pem) and (not self.tls_verify) and ALLOW_PLAINTEXT_FALLBACK and (
                'WRONG_VERSION_NUMBER' in msg or 'UNKNOWN_PROTOCOL' in msg or 'HTTP_REQUEST' in msg
            ):
                # Re-dial plaintext
                raw2, err2, dial_info2 = _dial_tcp_target(self.peer_host, self.peer_port, DIAL_CONNECT_TIMEOUT)
                self._set_happy_eyeballs_state(dial_info2)
                if not raw2:
                    return None, '', f'dial_failed: {err2}'
                try:
                    raw2.settimeout(None)
                    _set_keepalive(raw2)
                    return raw2, 'plain', ''
                except Exception as exc2:
                    _safe_close(raw2)
                    return None, '', f'dial_failed: {exc2}'
            _safe_close(raw)
            return None, '', f'dial_tls_failed: {exc}'
        except Exception as exc:
            # Some plaintext servers will immediately close when they see a TLS ClientHello,
            # which can surface as ConnectionResetError (instead of an ssl.SSLError).
            # When we are allowed to fall back to plaintext (i.e. TLS verification is not
            # required), treat this as a strong signal that the peer is running without TLS.
            if (not self.server_cert_pem) and (not self.tls_verify) and ALLOW_PLAINTEXT_FALLBACK and isinstance(exc, ConnectionResetError):
                _safe_close(raw)
                raw2, err2, dial_info2 = _dial_tcp_target(self.peer_host, self.peer_port, DIAL_CONNECT_TIMEOUT)
                self._set_happy_eyeballs_state(dial_info2)
                if not raw2:
                    return None, '', f'dial_failed: {err2}'
                try:
                    raw2.settimeout(None)
                    _set_keepalive(raw2)
                    return raw2, 'plain', ''
                except Exception as exc2:
                    _safe_close(raw2)
                    return None, '', f'dial_failed: {exc2}'

            _safe_close(raw)
            return None, '', f'dial_tls_failed: {exc}'

    def _hello(self, ss: Any, dial_mode: str) -> Tuple[bool, str, Optional[int]]:
        """Perform authenticated hello.

        Returns: (ok, err, handshake_ms)
        """
        t0 = _now()
        nonce = uuid.uuid4().hex
        ts = int(_now())
        sig = _hmac_sig(self.token, self.node_id, ts, nonce)

        hello = {
            'type': 'hello',
            'magic': INTRANET_MAGIC,
            'ver': INTRANET_PROTO_VER,
            'node_id': self.node_id,
            'token': self.token,
            'ts': ts,
            'nonce': nonce,
            'sig': sig,
            'dial_mode': dial_mode,
        }
        aliases: List[Dict[str, str]] = []
        for tk in self.tokens[1:64]:
            aliases.append({'token': tk, 'sig': _hmac_sig(tk, self.node_id, ts, nonce)})
        if aliases:
            hello['token_aliases'] = aliases

        try:
            ss.sendall(_json_line(hello))
        except Exception as exc:
            return False, f'hello_send_failed: {exc}', None

        try:
            # Wait hello_ok
            ss.settimeout(HELLO_TIMEOUT)
            line = _recv_line(ss)
            ss.settimeout(None)
        except Exception as exc:
            return False, f'hello_timeout: {exc}', None

        if not line:
            return False, 'hello_no_response', None

        if line.startswith('HTTP/') or line.startswith('GET ') or line.startswith('POST '):
            return False, 'peer_is_http_proxy', None

        try:
            resp = json.loads(line)
        except Exception:
            return False, 'hello_bad_response', None

        if str(resp.get('type') or '') == 'hello_ok':
            hs = int((_now() - t0) * 1000)
            return True, '', hs

        if str(resp.get('type') or '') == 'hello_err':
            return False, str(resp.get('error') or 'hello_err'), None

        return False, 'hello_unexpected_response', None

    def _loop(self) -> None:
        backoff = 1.0
        seq = 0
        last_rtt: Optional[int] = None

        while not self._stop.is_set():
            self._set_state(last_attempt_at=_now(), connected=False)
            ss, dial_mode, dial_err = self._dial()
            if not ss:
                self._set_state(last_error=dial_err, dial_mode='', connected=False)
                time.sleep(min(10.0, backoff))
                backoff = min(10.0, backoff * 1.6 + 0.2)
                continue

            # hello
            ok, herr, hs_ms = self._hello(ss, dial_mode)
            if not ok:
                self._set_state(last_error=herr, dial_mode=dial_mode, connected=False, handshake_ms=None)
                _log('client_hello_failed', peer=f'{self.peer_host}:{self.peer_port}', token=_mask_token(self.token), dial_mode=dial_mode, error=herr)
                _safe_close(ss)
                time.sleep(min(10.0, backoff))
                backoff = min(10.0, backoff * 1.6 + 0.2)
                continue

            backoff = 1.0
            now = _now()
            if self._had_connected:
                self._reconnects += 1
            self._had_connected = True
            self._set_state(
                connected=True,
                dial_mode=dial_mode,
                last_connected_at=now,
                last_hello_ok_at=now,
                last_pong_at=now,
                rtt_ms=None,
                handshake_ms=hs_ms,
                last_error='',
                reconnects=int(self._reconnects),
                ping_sent=0,
                pong_recv=0,
                loss_pct=0.0,
                jitter_ms=0,
            )
            self._set_ctrl_sock(ss)
            _log('client_connected', peer=f'{self.peer_host}:{self.peer_port}', token=_mask_token(self.token), dial_mode=dial_mode, handshake_ms=hs_ms)

            last_ping = 0.0
            while not self._stop.is_set():
                # send ping
                if (_now() - last_ping) >= PING_INTERVAL:
                    seq += 1
                    ping = {'type': 'ping', 'seq': seq, 'ts': _now_ms()}
                    if last_rtt is not None:
                        ping['rtt_ms'] = int(last_rtt)
                    if not self._send_control(ping):
                        self._set_state(last_error='control_send_failed')
                        break
                    with self._state_lock:
                        self._state.ping_sent = int(self._state.ping_sent) + 1
                    last_ping = _now()

                # pong timeout protection
                st = self.get_state()
                lp = float(st.get('last_pong_at') or 0)
                if lp and (_now() - lp) > PONG_TIMEOUT:
                    self._set_state(last_error='pong_timeout')
                    break

                line = ''
                try:
                    ss.settimeout(CONTROL_RECV_TIMEOUT)
                    line = _recv_line(ss)
                except socket.timeout:
                    continue
                except Exception as exc:
                    self._set_state(last_error=f'control_recv_failed: {exc}')
                    break
                finally:
                    try:
                        ss.settimeout(None)
                    except Exception:
                        pass

                if not line:
                    self._set_state(last_error='control_closed')
                    break

                if line.startswith('HTTP/') or line.startswith('GET ') or line.startswith('POST '):
                    self._set_state(last_error='peer_is_http_proxy')
                    break

                try:
                    msg = json.loads(line)
                except Exception:
                    continue

                t = str(msg.get('type') or '')

                if t == 'pong':
                    try:
                        echo_ts = int(msg.get('echo_ts') or 0)
                    except Exception:
                        echo_ts = 0
                    now_ts = _now()
                    with self._state_lock:
                        self._state.pong_recv = int(self._state.pong_recv) + 1
                        if echo_ts > 0:
                            rtt = max(0, _now_ms() - echo_ts)
                            last_rtt = int(rtt)
                            prev = self._state.rtt_ms
                            if prev is not None:
                                diff = abs(int(rtt) - int(prev))
                                old_jitter = int(self._state.jitter_ms or 0)
                                self._state.jitter_ms = int((old_jitter * 7 + diff) / 8)
                            self._state.rtt_ms = int(rtt)
                        self._state.last_pong_at = now_ts
                        sent = max(1, int(self._state.ping_sent or 0))
                        recv = max(0, int(self._state.pong_recv or 0))
                        lost = max(0, sent - recv)
                        self._state.loss_pct = round((float(lost) * 100.0) / float(sent), 2)
                    continue

                if t == 'open':
                    if not self._open_sem.acquire(blocking=False):
                        _log('client_open_overload', peer=f'{self.peer_host}:{self.peer_port}', token=_mask_token(self.token))
                        continue
                    threading.Thread(target=self._handle_open_guarded, args=(msg,), daemon=True).start()
                    continue

                if t in ('open_rev_ok', 'open_rev_err'):
                    conn_id = str(msg.get('conn_id') or '').strip()
                    if not conn_id:
                        continue
                    with self._rev_open_lock:
                        row = self._rev_open_wait.get(conn_id)
                        if isinstance(row, dict):
                            row['ok'] = (t == 'open_rev_ok')
                            row['error'] = str(msg.get('error') or '')
                            ev = row.get('event')
                            if isinstance(ev, threading.Event):
                                ev.set()
                    continue

            # disconnected
            self._set_state(connected=False)
            self._set_ctrl_sock(None)
            self._fail_rev_open_waiters('control_closed')
            _safe_close(ss)
            # next loop with backoff

    def _open_data(self) -> Tuple[Optional[Any], str]:
        ss, dial_mode, err = self._dial()
        if not ss:
            return None, err
        return ss, ''

    def _handle_open(self, msg: Dict[str, Any]) -> None:
        conn_id = str(msg.get('conn_id') or '')
        proto = str(msg.get('proto') or 'tcp').lower()
        target = str(msg.get('target') or '')
        req_token = str(msg.get('token') or self.token).strip()
        if not conn_id or not target or not req_token:
            return
        if not self.owns_token(req_token):
            _log('client_open_token_reject', peer=f'{self.peer_host}:{self.peer_port}', token=_mask_token(self.token), req_token=_mask_token(req_token))
            return
        if proto == 'udp':
            self._handle_udp(conn_id, target, req_token)
        else:
            self._handle_tcp(conn_id, target, req_token)

    def _handle_open_guarded(self, msg: Dict[str, Any]) -> None:
        try:
            self._handle_open(msg)
        finally:
            try:
                self._open_sem.release()
            except Exception:
                pass

    def _handle_tcp(self, conn_id: str, target: str, req_token: str) -> None:
        try:
            host, port = _split_hostport(target)
            out, dial_err, _dial_info = _dial_tcp_target(host, int(port), 6.0)
            if not out:
                raise OSError(str(dial_err or 'dial_failed'))
            out.settimeout(None)
            _set_keepalive(out)
        except Exception as exc:
            ds, err = self._open_data()
            if ds:
                try:
                    ds.sendall(_json_line({'type': 'data', 'proto': 'tcp', 'token': req_token, 'conn_id': conn_id, 'ok': False, 'error': str(exc)}))
                except Exception:
                    pass
                _safe_close(ds)
            else:
                _log('data_open_failed', target=target, proto='tcp', error=err)
            return

        ds, err = self._open_data()
        if not ds:
            _safe_close(out)
            _log('data_dial_failed', target=target, proto='tcp', error=err)
            return
        try:
            ds.sendall(_json_line({'type': 'data', 'proto': 'tcp', 'token': req_token, 'conn_id': conn_id, 'ok': True}))
        except Exception:
            _safe_close(ds)
            _safe_close(out)
            return
        _relay_tcp(out, ds)

    def _handle_udp(self, conn_id: str, target: str, req_token: str) -> None:
        us: Optional[socket.socket] = None
        try:
            host, port = _split_hostport(target)
            infos = _resolve_addrinfos(host, int(port), socket.SOCK_DGRAM, max_addrs=DIAL_HAPPY_EYEBALLS_MAX_ADDRS)
            if not infos:
                raise OSError('resolve_no_addr')
            last_exc: Optional[Exception] = None
            for family, stype, proto, sockaddr in infos:
                cand: Optional[socket.socket] = None
                try:
                    cand = socket.socket(family, stype, proto)
                    _set_socket_buffers(cand)
                    cand.connect(sockaddr)
                    cand.settimeout(1.0)
                    us = cand
                    break
                except Exception as exc2:
                    last_exc = exc2
                    _safe_close(cand)
            if us is None:
                if last_exc is not None:
                    raise last_exc
                raise OSError('udp_connect_failed')
        except Exception as exc:
            ds, err = self._open_data()
            if ds:
                try:
                    ds.sendall(_json_line({'type': 'data_udp', 'proto': 'udp', 'token': req_token, 'conn_id': conn_id, 'ok': False, 'error': str(exc)}))
                except Exception:
                    pass
                _safe_close(ds)
            else:
                _log('data_open_failed', target=target, proto='udp', error=err)
            return

        ds, err = self._open_data()
        if not ds:
            _safe_close(us)
            _log('data_dial_failed', target=target, proto='udp', error=err)
            return
        try:
            ds.sendall(_json_line({'type': 'data_udp', 'proto': 'udp', 'token': req_token, 'conn_id': conn_id, 'ok': True}))
        except Exception:
            _safe_close(ds)
            _safe_close(us)
            return

        stop = threading.Event()
        threading.Thread(target=_udp_from_data_to_target, args=(ds, us, stop), daemon=True).start()
        threading.Thread(target=_udp_from_target_to_data, args=(ds, us, stop), daemon=True).start()
        while not stop.wait(UDP_BRIDGE_STOP_WAIT):
            pass
        _safe_close(ds)
        _safe_close(us)


def _recv_exact(sock: Any, n: int) -> bytes:
    need = int(n)
    if need <= 0:
        return b''
    buf = bytearray(need)
    view = memoryview(buf)
    got = 0
    while got < need:
        try:
            if hasattr(sock, 'recv_into'):
                cnt = sock.recv_into(view[got:], need - got)
                if not cnt:
                    return b''
                got += int(cnt)
                continue
            chunk = sock.recv(need - got)
        except Exception:
            return b''
        if not chunk:
            return b''
        ln = len(chunk)
        view[got: got + ln] = chunk
        got += ln
    return bytes(buf)


def _relay_tcp(a: socket.socket, b: Any, limiter: Optional[_ByteRateLimiter] = None) -> None:
    """Bidirectional relay between a plain TCP socket and a (TLS/plain) tunnel socket.

    Keep half-close semantics: EOF on one direction only shuts down peer write side
    and allows the opposite direction to drain pending response bytes.
    """
    stop = threading.Event()
    done_ab = threading.Event()
    done_ba = threading.Event()
    chunk_size = int(TCP_RELAY_CHUNK)
    drain_timeout = float(TCP_RELAY_DRAIN_TIMEOUT)

    def _shutdown_write(sock_obj: Any) -> None:
        try:
            sock_obj.shutdown(socket.SHUT_WR)
        except Exception:
            pass

    def _pump(src, dst, done_ev: threading.Event):
        use_recv_into = hasattr(src, 'recv_into')
        buf = bytearray(chunk_size) if use_recv_into else None
        view = memoryview(buf) if buf is not None else None
        try:
            while not stop.is_set():
                if view is not None:
                    n = src.recv_into(view)
                    if not n:
                        break
                    if limiter is not None:
                        limiter.consume(int(n))
                    dst.sendall(view[: int(n)])
                    continue
                data = src.recv(chunk_size)
                if not data:
                    break
                if limiter is not None:
                    limiter.consume(len(data))
                dst.sendall(data)
        except Exception:
            stop.set()
        finally:
            _shutdown_write(dst)
            done_ev.set()

    t1 = threading.Thread(target=_pump, args=(a, b, done_ab), daemon=True)
    t2 = threading.Thread(target=_pump, args=(b, a, done_ba), daemon=True)
    t1.start()
    t2.start()
    first_done_at = 0.0
    while True:
        if done_ab.is_set() and done_ba.is_set():
            break
        if stop.wait(TCP_RELAY_STOP_WAIT):
            break
        if done_ab.is_set() or done_ba.is_set():
            if first_done_at <= 0.0:
                first_done_at = _now()
            elif (_now() - first_done_at) >= drain_timeout:
                break
    _safe_close(a)
    _safe_close(b)
    t1.join(timeout=0.2)
    t2.join(timeout=0.2)


def _relay_udp_stream(data_sock: Any, udp_sock: socket.socket) -> None:
    stop = threading.Event()
    threading.Thread(target=_udp_from_data_to_target, args=(data_sock, udp_sock, stop), daemon=True).start()
    threading.Thread(target=_udp_from_target_to_data, args=(data_sock, udp_sock, stop), daemon=True).start()
    while not stop.wait(UDP_BRIDGE_STOP_WAIT):
        pass
    _safe_close(data_sock)
    _safe_close(udp_sock)


def _udp_from_data_to_target(data_sock: Any, udp_sock: socket.socket, stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            hdr = _recv_exact(data_sock, 4)
            if not hdr:
                break
            (n,) = struct.unpack('!I', hdr)
            if n <= 0 or n > MAX_FRAME:
                break
            payload = _recv_exact(data_sock, n)
            if not payload:
                break
            udp_sock.send(payload)
    except Exception:
        pass
    stop.set()


def _udp_from_target_to_data(data_sock: Any, udp_sock: socket.socket, stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            try:
                payload = udp_sock.recv(MAX_FRAME)
            except socket.timeout:
                continue
            if not payload:
                continue
            frame = struct.pack('!I', len(payload)) + payload
            data_sock.sendall(frame)
    except Exception:
        pass
    stop.set()


def _split_hostport(addr: str) -> Tuple[str, int]:
    """Parse host:port.

    - IPv6 must use bracket form: [2001:db8::1]:443
    - Raises ValueError when port is missing/invalid.
    """
    s = (addr or '').strip()
    if not s:
        raise ValueError('empty address')

    # URL form
    if '://' in s:
        try:
            u = urlparse(s)
            host = (u.hostname or '').strip()
            port = int(u.port or 0)
        except Exception:
            raise ValueError('address must include host and valid port')
        if not host or port <= 0 or port > 65535:
            raise ValueError('address must include host and valid port')
        return host, port

    # Bracketed IPv6
    if s.startswith('['):
        if ']' not in s:
            raise ValueError('invalid IPv6 bracket address')
        host = s.split(']')[0][1:].strip()
        rest = s.split(']')[1]
        if not rest.startswith(':'):
            raise ValueError('missing port')
        p = rest[1:]
        if not p.isdigit():
            raise ValueError('invalid port')
        port = int(p)
        if port <= 0 or port > 65535:
            raise ValueError('invalid port')
        return host, port

    # Unbracketed IPv6 is ambiguous because it contains ':'
    if s.count(':') > 1:
        raise ValueError('IPv6 must use [addr]:port')

    if ':' in s:
        host, p = s.rsplit(':', 1)
        if not p.isdigit():
            raise ValueError('invalid port')
        port = int(p)
        if port <= 0 or port > 65535:
            raise ValueError('invalid port')
        return host.strip(), port

    raise ValueError('missing port (expected host:port)')


def _split_hostport_allow_zero(addr: str) -> Tuple[str, int]:
    """Parse host:port while allowing port 0 for placeholder listen addresses."""
    s = (addr or '').strip()
    if not s:
        raise ValueError('empty address')

    if '://' in s:
        try:
            u = urlparse(s)
            host = (u.hostname or '').strip()
            port = int(u.port or 0)
        except Exception:
            raise ValueError('address must include host and valid port')
        if not host or port < 0 or port > 65535:
            raise ValueError('address must include host and valid port')
        return host, port

    if s.startswith('['):
        if ']' not in s:
            raise ValueError('invalid IPv6 bracket address')
        host = s.split(']')[0][1:].strip()
        rest = s.split(']')[1]
        if not rest.startswith(':'):
            raise ValueError('missing port')
        p = rest[1:]
        if not p.isdigit():
            raise ValueError('invalid port')
        port = int(p)
        if port < 0 or port > 65535:
            raise ValueError('invalid port')
        return host, port

    if s.count(':') > 1:
        raise ValueError('IPv6 must use [addr]:port')

    if ':' in s:
        host, p = s.rsplit(':', 1)
        if not p.isdigit():
            raise ValueError('invalid port')
        port = int(p)
        if port < 0 or port > 65535:
            raise ValueError('invalid port')
        return host.strip(), port

    raise ValueError('missing port (expected host:port)')


def _listen_port_or_neg1(addr: str) -> int:
    try:
        _host, port = _split_hostport_allow_zero(addr)
        return int(port)
    except Exception:
        return -1



def _bind_socket(host: str, port: int, socktype: int) -> socket.socket:
    """Bind a socket (TCP/UDP) with IPv4/IPv6 support."""
    bind_host = (host or '').strip()
    if bind_host in ('', '*'):
        bind_host = None  # wildcard

    last_exc: Optional[Exception] = None
    infos = socket.getaddrinfo(bind_host, int(port), socket.AF_UNSPEC, socktype, 0, socket.AI_PASSIVE)
    for family, stype, proto, _canon, sockaddr in infos:
        s: Optional[socket.socket] = None
        try:
            s = socket.socket(family, stype, proto)
            _set_socket_buffers(s)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # type: ignore[attr-defined]
            except Exception:
                pass
            if family == socket.AF_INET6:
                try:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except Exception:
                    pass
            s.bind(sockaddr)
            return s
        except Exception as exc:
            last_exc = exc
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            continue

    if last_exc:
        raise last_exc
    raise OSError('bind failed')



class IntranetManager:
    """Supervise intranet tunnels based on pool_full.json endpoints."""

    def __init__(self, node_id: int):
        self.node_id = int(node_id)
        self._lock = threading.Lock()
        self._servers: Dict[int, _TunnelServer] = {}
        self._tcp_listeners: Dict[str, _TCPListener] = {}  # sync_id -> listener
        self._udp_listeners: Dict[str, _UDPListener] = {}
        self._client_tcp_listeners: Dict[str, _ClientTCPListener] = {}
        self._client_udp_listeners: Dict[str, _ClientUDPListener] = {}
        self._clients: Dict[str, _TunnelClient] = {}  # key -> client
        self._client_token_index: Dict[str, str] = {}  # token -> client key
        self._rule_client_key: Dict[str, str] = {}  # sync_id -> client key
        self._last_rules: Dict[str, IntranetRule] = {}

    def apply_from_pool(self, pool: Dict[str, Any]) -> None:
        rules = self._parse_rules(pool)
        with self._lock:
            self._apply_rules_locked(rules)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            servers = []
            for p, s in self._servers.items():
                tls_on = bool(getattr(s, '_ssl_ctx', None) is not None)
                srv_stats = s.stats_snapshot()
                sessions = []
                with getattr(s, '_sessions_lock'):
                    sess_map: Dict[int, Dict[str, Any]] = {}
                    for tok, sess in list(getattr(s, '_sessions', {}).items()):
                        sid = id(sess)
                        item = sess_map.get(sid)
                        if not item:
                            item = {
                                'tokens': [],
                                'node_id': sess.node_id,
                                'dial_mode': sess.dial_mode,
                                'legacy': bool(sess.legacy),
                                'connected_at': int(sess.connected_at),
                                'last_seen_at': int(sess.last_seen),
                                'rtt_ms': sess.rtt_ms,
                            }
                            sess_map[sid] = item
                        item['tokens'].append(_mask_token(tok))
                    for item in sess_map.values():
                        sessions.append({
                            'token': (item.get('tokens') or [''])[0],
                            'tokens': item.get('tokens') or [],
                            'token_count': len(item.get('tokens') or []),
                            'node_id': item.get('node_id'),
                            'dial_mode': item.get('dial_mode'),
                            'legacy': bool(item.get('legacy')),
                            'connected_at': int(item.get('connected_at') or 0),
                            'last_seen_at': int(item.get('last_seen_at') or 0),
                            'rtt_ms': item.get('rtt_ms'),
                        })
                servers.append({'port': int(p), 'tls': tls_on, 'sessions': sessions, 'stats': srv_stats})

            clients = []
            for key, c in self._clients.items():
                st = c.get_state()
                st['key'] = key
                clients.append(st)

            # per rule quick view
            rules = []
            for sync_id, r in self._last_rules.items():
                rules.append({
                    'sync_id': sync_id,
                    'role': r.role,
                    'listen': r.listen,
                    'peer_host': r.peer_host,
                    'port': r.tunnel_port,
                    'token': _mask_token(r.token),
                    'token_count': len(r.tokens or [r.token]),
                    'tls_verify': bool(r.tls_verify),
                    'qos': {
                        'bandwidth_kbps': int(r.qos_bandwidth_kbps or 0),
                        'max_conns': int(r.qos_max_conns or 0),
                        'conn_rate': int(r.qos_conn_rate or 0),
                    },
                    'acl': {
                        'allow_sources': list(r.acl_allow_sources or []),
                        'deny_sources': list(r.acl_deny_sources or []),
                        'allow_hours': list(r.acl_allow_hours or []),
                        'allow_tokens': list(r.acl_allow_tokens or []),
                    },
                    'handshake': self.handshake_health(r.sync_id, {
                        'intranet_role': r.role,
                        'intranet_token': r.token,
                        'intranet_server_port': r.tunnel_port,
                        'intranet_peer_host': r.peer_host,
                    }),
                })

            summary = {
                'servers': len(servers),
                'clients': len(clients),
                'rules': len(rules),
                'active_tcp_relays': sum(int((s.get('stats') or {}).get('tcp_relays_active') or 0) for s in servers),
                'active_udp_sessions': sum(int((s.get('stats') or {}).get('udp_sessions_active') or 0) for s in servers),
                'open_fail': sum(int((s.get('stats') or {}).get('open_fail') or 0) for s in servers),
                'reject_overload': sum(int((s.get('stats') or {}).get('reject_overload') or 0) for s in servers),
                'acl_reject': sum(int((s.get('stats') or {}).get('acl_reject') or 0) for s in servers),
                'qos_reject_conn_rate': sum(int((s.get('stats') or {}).get('qos_reject_conn_rate') or 0) for s in servers),
                'qos_reject_max_conns': sum(int((s.get('stats') or {}).get('qos_reject_max_conns') or 0) for s in servers),
                'control_reconnect': sum(int((s.get('stats') or {}).get('control_reconnect') or 0) for s in servers),
            }

            return {
                'servers': servers,
                'tcp_rules': list(self._tcp_listeners.keys()),
                'udp_rules': list(self._udp_listeners.keys()),
                'client_tcp_rules': list(self._client_tcp_listeners.keys()),
                'client_udp_rules': list(self._client_udp_listeners.keys()),
                'clients': clients,
                'rules': rules,
                'summary': summary,
            }

    def _route_cards(self, sync_id: str) -> List[Dict[str, Any]]:
        sid = str(sync_id or '').strip()
        if not sid:
            return []
        out: List[Dict[str, Any]] = []
        tl = self._tcp_listeners.get(sid)
        if tl is not None:
            try:
                x = tl.snapshot_route_info()
                if isinstance(x, dict):
                    out.append(x)
            except Exception:
                pass
        ul = self._udp_listeners.get(sid)
        if ul is not None:
            try:
                x = ul.snapshot_route_info()
                if isinstance(x, dict):
                    out.append(x)
            except Exception:
                pass
        ctl = self._client_tcp_listeners.get(sid)
        if ctl is not None:
            try:
                x = ctl.snapshot_route_info()
                if isinstance(x, dict):
                    row = dict(x)
                    row['mode'] = 'reverse_open'
                    out.append(row)
            except Exception:
                pass
        cul = self._client_udp_listeners.get(sid)
        if cul is not None:
            try:
                x = cul.snapshot_route_info()
                if isinstance(x, dict):
                    row = dict(x)
                    row['mode'] = 'reverse_open'
                    out.append(row)
            except Exception:
                pass
        return out

    def handshake_health(self, sync_id: str, ex: Dict[str, Any]) -> Dict[str, Any]:
        """Return health payload for panel handshake check.

        Shape:
          {ok:bool, latency_ms?:int, error?:str, message?:str}
        """
        role = str(ex.get('intranet_role') or '').strip()
        token = str(ex.get('intranet_token') or '').strip()
        try:
            port = int(ex.get('intranet_server_port') or DEFAULT_TUNNEL_PORT)
        except Exception:
            port = DEFAULT_TUNNEL_PORT
        route_cards = self._route_cards(sync_id)

        # Server side: check control session presence
        if role == 'server':
            srv = self._servers.get(port)
            if not srv:
                return {'ok': False, 'error': 'server_not_running', 'route_cards': route_cards}
            sess = srv.get_session(token)
            if not sess:
                return {'ok': False, 'error': 'no_client_connected', 'route_cards': route_cards}
            latency = sess.rtt_ms
            if latency is None:
                latency = int(max(0.0, (_now() - sess.last_seen) * 1000.0))
            payload: Dict[str, Any] = {
                'ok': True,
                'latency_ms': int(latency),
                'dial_mode': str(sess.dial_mode or ''),
                'reconnects': int(srv.token_reconnects(token)),
                'token_count': len(getattr(sess, 'tokens', set()) or {token}),
                'route_cards': route_cards,
            }
            if sess.legacy:
                payload['message'] = 'legacy_client'
            return payload

        # Client side: check client runtime
        if role == 'client':
            peer_host = str(ex.get('intranet_peer_host') or '').strip()
            key = ''
            sid = str(sync_id or '').strip()
            if sid:
                key = str(self._rule_client_key.get(sid) or '')
            if (not key) and token:
                key = str(self._client_token_index.get(token) or '')
            if not key:
                # Backward-compatible fallback:
                # find a client by token/peer/port even when key schema changes.
                for ck, cv in self._clients.items():
                    try:
                        st0 = cv.get_state()
                    except Exception:
                        continue
                    if token and (not cv.owns_token(token)):
                        continue
                    if peer_host and str(st0.get('peer_host') or '').strip() != peer_host:
                        continue
                    try:
                        p0 = int(st0.get('peer_port') or 0)
                    except Exception:
                        p0 = 0
                    if port > 0 and p0 != int(port):
                        continue
                    key = ck
                    break
            c = self._clients.get(key) if key else None
            if not c:
                return {'ok': False, 'error': 'client_not_running', 'route_cards': route_cards}
            st = c.get_state()
            he = {
                'enabled': bool(st.get('he_enabled')),
                'mode': str(st.get('he_mode') or ''),
                'winner_family': str(st.get('he_family') or ''),
                'winner_addr': str(st.get('he_addr') or ''),
                'attempts': int(st.get('he_attempts') or 0),
                'last_at': int(st.get('he_last_at') or 0),
            }
            if st.get('connected'):
                payload2: Dict[str, Any] = {
                    'ok': True,
                    'dial_mode': str(st.get('dial_mode') or ''),
                    'reconnects': int(st.get('reconnects') or 0),
                    'loss_pct': float(st.get('loss_pct') or 0.0),
                    'jitter_ms': int(st.get('jitter_ms') or 0),
                    'token_count': int(st.get('token_count') or 1),
                    'ping_sent': int(st.get('ping_sent') or 0),
                    'pong_recv': int(st.get('pong_recv') or 0),
                    'last_attempt_at': int(st.get('last_attempt_at') or 0),
                    'last_connected_at': int(st.get('last_connected_at') or 0),
                    'happy_eyeballs': he,
                    'route_cards': route_cards,
                }
                if st.get('rtt_ms') is not None:
                    payload2['latency_ms'] = int(st.get('rtt_ms') or 0)
                elif st.get('handshake_ms') is not None:
                    payload2['latency_ms'] = int(st.get('handshake_ms') or 0)
                return payload2
            err = str(st.get('last_error') or '').strip()
            if not err:
                err = 'dialing' if int(st.get('last_attempt_at') or 0) > 0 else 'not_connected'
            return {
                'ok': False,
                'error': err,
                'dial_mode': str(st.get('dial_mode') or ''),
                'reconnects': int(st.get('reconnects') or 0),
                'loss_pct': float(st.get('loss_pct') or 0.0),
                'jitter_ms': int(st.get('jitter_ms') or 0),
                'token_count': int(st.get('token_count') or 1),
                'ping_sent': int(st.get('ping_sent') or 0),
                'pong_recv': int(st.get('pong_recv') or 0),
                'last_attempt_at': int(st.get('last_attempt_at') or 0),
                'last_connected_at': int(st.get('last_connected_at') or 0),
                'happy_eyeballs': he,
                'route_cards': route_cards,
            }

        return {'ok': None, 'message': 'unknown_role'}

    def _parse_rules(self, pool: Dict[str, Any]) -> Dict[str, IntranetRule]:
        out: Dict[str, IntranetRule] = {}
        eps = pool.get('endpoints') or []
        if not isinstance(eps, list):
            return out
        for e in eps:
            if not isinstance(e, dict):
                continue
            ex = e.get('extra_config')
            if not isinstance(ex, dict):
                continue
            role = str(ex.get('intranet_runtime_role') or ex.get('intranet_role') or '').strip()
            if role not in ('server', 'client'):
                continue
            sync_id = str(ex.get('sync_id') or '').strip() or uuid.uuid4().hex
            listen = str(e.get('listen') or '').strip()
            if role == 'client' and _listen_port_or_neg1(listen) <= 0:
                sender_listen = str(ex.get('sync_sender_listen') or ex.get('intranet_sender_listen') or '').strip()
                if sender_listen:
                    listen = sender_listen
            protocol = str(e.get('protocol') or 'tcp+udp').strip().lower() or 'tcp+udp'
            relay_mode = str(ex.get('sync_tunnel_mode') or ex.get('sync_tunnel_type') or '').strip().lower()
            if role == 'client' and relay_mode in ('relay', 'wss_relay') and protocol == 'tcp':
                # Backward compatibility: old relay rules were persisted as TCP-only.
                protocol = 'tcp+udp'
            balance = str(e.get('balance') or 'roundrobin').strip() or 'roundrobin'
            remotes_raw: List[str] = []
            if isinstance(e.get('remote'), str) and str(e.get('remote') or '').strip():
                remotes_raw.append(str(e.get('remote') or '').strip())
            if isinstance(e.get('remotes'), list):
                remotes_raw += [str(x).strip() for x in e.get('remotes') if str(x).strip()]
            if isinstance(e.get('extra_remotes'), list):
                remotes_raw += [str(x).strip() for x in e.get('extra_remotes') if str(x).strip()]
            seen_remotes: set[str] = set()
            remotes: List[str] = []
            for r in remotes_raw:
                if r in seen_remotes:
                    continue
                seen_remotes.add(r)
                remotes.append(r)
            if remotes:
                algo_bal, ws_bal = _parse_balance(balance, len(remotes))
                has_explicit_weights = ":" in str(balance)
                used_weight_override = False
                if (
                    algo_bal in _WEIGHTED_BALANCE_ALGOS
                    and (not has_explicit_weights)
                    and isinstance(e.get('weights'), list)
                ):
                    raw_ws = [str(x).strip() for x in (e.get('weights') or []) if str(x).strip()]
                    if len(raw_ws) == len(remotes) and all(x.isdigit() and int(x) > 0 for x in raw_ws):
                        ws_bal = [int(x) for x in raw_ws]
                        used_weight_override = True
                if (
                    len(remotes) > 1
                    and algo_bal in _WEIGHTED_BALANCE_ALGOS
                    and ws_bal
                    and (has_explicit_weights or used_weight_override)
                ):
                    balance = f"{algo_bal}: " + ", ".join(str(int(max(1, w))) for w in ws_bal)
                else:
                    balance = str(algo_bal)
            token = str(ex.get('intranet_token') or '').strip()
            tokens: List[str] = []
            if token:
                tokens.append(token)
            raw_tokens = ex.get('intranet_tokens')
            if isinstance(raw_tokens, list):
                for tk in raw_tokens:
                    st = str(tk or '').strip()
                    if st:
                        tokens.append(st)
            now_ts = int(_now())
            raw_grace = ex.get('intranet_token_grace')
            if isinstance(raw_grace, list):
                for it in raw_grace:
                    if not isinstance(it, dict):
                        continue
                    st = str(it.get('token') or '').strip()
                    if not st:
                        continue
                    try:
                        exp = int(it.get('expires_at') or 0)
                    except Exception:
                        exp = 0
                    if exp > now_ts:
                        tokens.append(st)
            seen_tokens: set[str] = set()
            uniq_tokens: List[str] = []
            for tk in tokens:
                if tk in seen_tokens:
                    continue
                seen_tokens.add(tk)
                uniq_tokens.append(tk)
            if not token and uniq_tokens:
                token = uniq_tokens[0]
            if not uniq_tokens and token:
                uniq_tokens = [token]
            try:
                peer_node_id = int(ex.get('intranet_peer_node_id') or 0)
            except Exception:
                peer_node_id = 0
            peer_host = str(ex.get('intranet_peer_host') or '').strip()
            try:
                tunnel_port = int(ex.get('intranet_server_port') or DEFAULT_TUNNEL_PORT)
            except Exception:
                tunnel_port = DEFAULT_TUNNEL_PORT
            server_cert_pem = str(ex.get('intranet_server_cert_pem') or '').strip()
            tls_verify = _truthy(ex.get('intranet_tls_verify'))

            qos = ex.get('qos') if isinstance(ex.get('qos'), dict) else {}
            net = e.get('network') if isinstance(e.get('network'), dict) else {}
            net_qos = net.get('qos') if isinstance(net.get('qos'), dict) else {}

            def _pick_qos(keys: Tuple[str, ...], sources: Tuple[Any, ...] = (qos, net_qos, ex, net, e)) -> Any:
                for src in sources:
                    if not isinstance(src, dict):
                        continue
                    for k in keys:
                        if k in src:
                            return src.get(k)
                return 0

            qos_bandwidth_kbps = _parse_nonneg_int(
                _pick_qos(('bandwidth_kbps', 'bandwidth_kbit', 'bandwidth_limit_kbps', 'qos_bandwidth_kbps'))
            )
            if qos_bandwidth_kbps <= 0:
                qos_bandwidth_mbps = _parse_nonneg_int(
                    _pick_qos(('bandwidth_mbps', 'bandwidth_limit_mbps', 'qos_bandwidth_mbps'))
                )
                if qos_bandwidth_mbps > 0:
                    qos_bandwidth_kbps = qos_bandwidth_mbps * 1024
            qos_max_conns = _parse_nonneg_int(
                _pick_qos(('max_conns', 'max_conn', 'max_connections', 'qos_max_conns'))
            )
            qos_conn_rate = _parse_nonneg_int(
                _pick_qos(('conn_rate', 'conn_per_sec', 'new_conn_per_sec', 'new_connections_per_sec', 'qos_conn_rate'))
            )

            acl_cfg = ex.get('intranet_acl') if isinstance(ex.get('intranet_acl'), dict) else {}
            acl_allow_sources = _normalize_str_list(
                acl_cfg.get('allow_sources') if isinstance(acl_cfg, dict) else ex.get('intranet_acl_allow_sources'),
                max_items=128,
                item_max_len=64,
            )
            acl_deny_sources = _normalize_str_list(
                acl_cfg.get('deny_sources') if isinstance(acl_cfg, dict) else ex.get('intranet_acl_deny_sources'),
                max_items=128,
                item_max_len=64,
            )
            acl_allow_hours = _normalize_str_list(
                acl_cfg.get('allow_hours') if isinstance(acl_cfg, dict) else ex.get('intranet_acl_allow_hours'),
                max_items=16,
                item_max_len=16,
            )
            acl_allow_tokens = _normalize_str_list(
                acl_cfg.get('allow_tokens') if isinstance(acl_cfg, dict) else ex.get('intranet_acl_allow_tokens'),
                max_items=64,
                item_max_len=96,
            )

            if not token:
                continue
            if role == 'server' and (not listen or not remotes):
                continue
            if role == 'client' and (not peer_host):
                continue

            out[sync_id] = IntranetRule(
                sync_id=sync_id,
                role=role,
                listen=listen,
                protocol=protocol,
                balance=balance,
                remotes=remotes,
                token=token,
                peer_node_id=peer_node_id,
                peer_host=peer_host,
                tunnel_port=tunnel_port,
                server_cert_pem=server_cert_pem,
                tokens=uniq_tokens,
                tls_verify=tls_verify,
                qos_bandwidth_kbps=qos_bandwidth_kbps,
                qos_max_conns=qos_max_conns,
                qos_conn_rate=qos_conn_rate,
                acl_allow_sources=acl_allow_sources,
                acl_deny_sources=acl_deny_sources,
                acl_allow_hours=acl_allow_hours,
                acl_allow_tokens=acl_allow_tokens,
            )
        return out

    def _apply_rules_locked(self, rules: Dict[str, IntranetRule]) -> None:
        tokens_by_port: Dict[int, set[str]] = {}
        for r in rules.values():
            if r.role == 'server':
                tokens_by_port.setdefault(r.tunnel_port, set()).update(r.tokens or [r.token])

        # start/stop servers
        for port, tokens in tokens_by_port.items():
            srv = self._servers.get(port)
            if srv and (not srv.is_running()):
                try:
                    srv.stop()
                except Exception:
                    pass
                self._servers.pop(port, None)
                srv = None
            if not srv:
                srv = _TunnelServer(port)
                srv.start()
                self._servers[port] = srv
            srv.set_allowed_tokens(tokens)
        for port in list(self._servers.keys()):
            if port not in tokens_by_port:
                self._servers[port].stop()
                self._servers.pop(port, None)

        # rule listeners on server role
        # NOTE: listeners are keyed by sync_id. When the server-side rule is edited (e.g. changing peer node),
        # the sync_id usually stays the same but token/remotes/listen may change. We must update/restart
        # existing listeners, otherwise the panel may show "handshake ok" while forwarding breaks.
        for sync_id, r in rules.items():
            if r.role != 'server':
                continue

            srv = self._servers.get(r.tunnel_port)
            if not srv:
                continue
            listen_port = _listen_port_or_neg1(r.listen)
            listen_enabled = bool(listen_port > 0)

            # TCP
            if ('tcp' in r.protocol) and listen_enabled:
                if sync_id not in self._tcp_listeners:
                    lis = _TCPListener(r, srv)
                    lis.start()
                    self._tcp_listeners[sync_id] = lis
                else:
                    # Update existing listener in-place; restart only when listen address or server changes.
                    lis = self._tcp_listeners.get(sync_id)
                    if lis:
                        old_rule = getattr(lis, 'rule', None)
                        old_listen = getattr(old_rule, 'listen', None)
                        need_restart = bool(getattr(lis, 'tunnel', None) is not srv or old_listen != r.listen)
                        if old_rule is not None:
                            if int(getattr(old_rule, 'qos_bandwidth_kbps', 0) or 0) != int(r.qos_bandwidth_kbps or 0):
                                need_restart = True
                            if int(getattr(old_rule, 'qos_max_conns', 0) or 0) != int(r.qos_max_conns or 0):
                                need_restart = True
                            if int(getattr(old_rule, 'qos_conn_rate', 0) or 0) != int(r.qos_conn_rate or 0):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_sources', []) or []) != list(r.acl_allow_sources or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_deny_sources', []) or []) != list(r.acl_deny_sources or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_hours', []) or []) != list(r.acl_allow_hours or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_tokens', []) or []) != list(r.acl_allow_tokens or []):
                                need_restart = True
                        if need_restart:
                            try:
                                lis.stop()
                            except Exception:
                                pass
                            lis2 = _TCPListener(r, srv)
                            lis2.start()
                            self._tcp_listeners[sync_id] = lis2
                        else:
                            lis.rule = r
                            lis.tunnel = srv
            else:
                if sync_id in self._tcp_listeners:
                    self._tcp_listeners[sync_id].stop()
                    self._tcp_listeners.pop(sync_id, None)

            # UDP
            if ('udp' in r.protocol) and listen_enabled:
                if sync_id not in self._udp_listeners:
                    ul = _UDPListener(r, srv)
                    ul.start()
                    self._udp_listeners[sync_id] = ul
                else:
                    ul = self._udp_listeners.get(sync_id)
                    if ul:
                        old_rule = getattr(ul, 'rule', None)
                        old_listen = getattr(old_rule, 'listen', None)
                        need_restart = bool(getattr(ul, 'tunnel', None) is not srv or old_listen != r.listen)
                        if old_rule is not None:
                            if int(getattr(old_rule, 'qos_bandwidth_kbps', 0) or 0) != int(r.qos_bandwidth_kbps or 0):
                                need_restart = True
                            if int(getattr(old_rule, 'qos_max_conns', 0) or 0) != int(r.qos_max_conns or 0):
                                need_restart = True
                            if int(getattr(old_rule, 'qos_conn_rate', 0) or 0) != int(r.qos_conn_rate or 0):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_sources', []) or []) != list(r.acl_allow_sources or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_deny_sources', []) or []) != list(r.acl_deny_sources or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_hours', []) or []) != list(r.acl_allow_hours or []):
                                need_restart = True
                            if list(getattr(old_rule, 'acl_allow_tokens', []) or []) != list(r.acl_allow_tokens or []):
                                need_restart = True
                        if need_restart:
                            try:
                                ul.stop()
                            except Exception:
                                pass
                            ul2 = _UDPListener(r, srv)
                            ul2.start()
                            self._udp_listeners[sync_id] = ul2
                        else:
                            ul.rule = r
                            ul.tunnel = srv
            else:
                if sync_id in self._udp_listeners:
                    self._udp_listeners[sync_id].stop()
                    self._udp_listeners.pop(sync_id, None)

        # stop removed listeners
        for sync_id in list(self._tcp_listeners.keys()):
            if (
                sync_id not in rules
                or rules[sync_id].role != 'server'
                or ('tcp' not in rules[sync_id].protocol)
                or _listen_port_or_neg1(rules[sync_id].listen) <= 0
            ):
                self._tcp_listeners[sync_id].stop()
                self._tcp_listeners.pop(sync_id, None)
        for sync_id in list(self._udp_listeners.keys()):
            if (
                sync_id not in rules
                or rules[sync_id].role != 'server'
                or ('udp' not in rules[sync_id].protocol)
                or _listen_port_or_neg1(rules[sync_id].listen) <= 0
            ):
                self._udp_listeners[sync_id].stop()
                self._udp_listeners.pop(sync_id, None)

        # clients on client role (group by peer+TLS profile; share one control channel across tokens/rules)
        client_groups: Dict[str, Dict[str, Any]] = {}
        rule_client_key: Dict[str, str] = {}
        for sync_id, r in rules.items():
            if r.role != 'client':
                continue
            cert_sig = hashlib.sha1((r.server_cert_pem or '').encode('utf-8')).hexdigest()[:16]
            key = f"{r.peer_host}:{r.tunnel_port}:{1 if r.tls_verify else 0}:{cert_sig}"
            grp = client_groups.get(key)
            if not grp:
                grp = {
                    'peer_host': r.peer_host,
                    'peer_port': r.tunnel_port,
                    'server_cert_pem': r.server_cert_pem,
                    'tls_verify': bool(r.tls_verify),
                    'tokens': [],
                    'seen': set(),
                }
                client_groups[key] = grp
            for tk in (r.tokens or [r.token]):
                st = str(tk or '').strip()
                if (not st) or (st in grp['seen']):
                    continue
                grp['seen'].add(st)
                grp['tokens'].append(st)
            rule_client_key[sync_id] = key

        desired_keys: set[str] = set(client_groups.keys())
        token_index: Dict[str, str] = {}

        for key, grp in client_groups.items():
            tokens = list(grp.get('tokens') or [])
            if not tokens:
                continue
            desired_keys.add(key)
            c = self._clients.get(key)
            if c and (not c.matches_config(grp.get('server_cert_pem') or '', bool(grp.get('tls_verify')), tokens)):
                c.stop()
                self._clients.pop(key, None)
                c = None
            if not c:
                c = _TunnelClient(
                    peer_host=str(grp.get('peer_host') or ''),
                    peer_port=int(grp.get('peer_port') or DEFAULT_TUNNEL_PORT),
                    token=str(tokens[0] or ''),
                    tokens=tokens,
                    node_id=self.node_id,
                    server_cert_pem=str(grp.get('server_cert_pem') or ''),
                    tls_verify=bool(grp.get('tls_verify')),
                )
                self._clients[key] = c
            c.start()
            for tk in tokens:
                token_index[str(tk)] = key

        for key in list(self._clients.keys()):
            if key not in desired_keys:
                self._clients[key].stop()
                self._clients.pop(key, None)

        # client-side local listeners (reverse-open mode)
        for sync_id, r in rules.items():
            if r.role != 'client':
                if sync_id in self._client_tcp_listeners:
                    self._client_tcp_listeners[sync_id].stop()
                    self._client_tcp_listeners.pop(sync_id, None)
                if sync_id in self._client_udp_listeners:
                    self._client_udp_listeners[sync_id].stop()
                    self._client_udp_listeners.pop(sync_id, None)
                continue

            ckey = str(rule_client_key.get(sync_id) or '')
            c = self._clients.get(ckey) if ckey else None
            listen_port = _listen_port_or_neg1(r.listen)
            enabled_tcp = bool(
                c is not None
                and listen_port > 0
                and ('tcp' in r.protocol)
                and bool(r.remotes)
            )
            enabled_udp = bool(
                c is not None
                and listen_port > 0
                and ('udp' in r.protocol)
                and bool(r.remotes)
            )

            if not enabled_tcp:
                if sync_id in self._client_tcp_listeners:
                    self._client_tcp_listeners[sync_id].stop()
                    self._client_tcp_listeners.pop(sync_id, None)
            else:
                cur = self._client_tcp_listeners.get(sync_id)
                if cur is None:
                    lis = _ClientTCPListener(r, c)  # type: ignore[arg-type]
                    lis.start()
                    self._client_tcp_listeners[sync_id] = lis
                else:
                    old_rule = getattr(cur, 'rule', None)
                    need_restart = bool(getattr(cur, 'client', None) is not c)
                    if old_rule is not None:
                        if getattr(old_rule, 'listen', '') != r.listen:
                            need_restart = True
                        if getattr(old_rule, 'balance', '') != r.balance:
                            need_restart = True
                        if getattr(old_rule, 'protocol', '') != r.protocol:
                            need_restart = True
                        if list(getattr(old_rule, 'remotes', []) or []) != list(r.remotes or []):
                            need_restart = True
                        if int(getattr(old_rule, 'qos_bandwidth_kbps', 0) or 0) != int(r.qos_bandwidth_kbps or 0):
                            need_restart = True
                        if int(getattr(old_rule, 'qos_max_conns', 0) or 0) != int(r.qos_max_conns or 0):
                            need_restart = True
                        if int(getattr(old_rule, 'qos_conn_rate', 0) or 0) != int(r.qos_conn_rate or 0):
                            need_restart = True
                        if list(getattr(old_rule, 'acl_allow_sources', []) or []) != list(r.acl_allow_sources or []):
                            need_restart = True
                        if list(getattr(old_rule, 'acl_deny_sources', []) or []) != list(r.acl_deny_sources or []):
                            need_restart = True
                        if list(getattr(old_rule, 'acl_allow_hours', []) or []) != list(r.acl_allow_hours or []):
                            need_restart = True
                        if list(getattr(old_rule, 'acl_allow_tokens', []) or []) != list(r.acl_allow_tokens or []):
                            need_restart = True

                    if need_restart:
                        try:
                            cur.stop()
                        except Exception:
                            pass
                        lis = _ClientTCPListener(r, c)  # type: ignore[arg-type]
                        lis.start()
                        self._client_tcp_listeners[sync_id] = lis
                    else:
                        cur.rule = r
                        cur.client = c  # type: ignore[assignment]

            if not enabled_udp:
                if sync_id in self._client_udp_listeners:
                    self._client_udp_listeners[sync_id].stop()
                    self._client_udp_listeners.pop(sync_id, None)
            else:
                curu = self._client_udp_listeners.get(sync_id)
                if curu is None:
                    ul = _ClientUDPListener(r, c)  # type: ignore[arg-type]
                    ul.start()
                    self._client_udp_listeners[sync_id] = ul
                else:
                    old_rule = getattr(curu, 'rule', None)
                    need_restart = bool(getattr(curu, 'client', None) is not c)
                    if old_rule is not None:
                        if getattr(old_rule, 'listen', '') != r.listen:
                            need_restart = True
                        if getattr(old_rule, 'balance', '') != r.balance:
                            need_restart = True
                        if getattr(old_rule, 'protocol', '') != r.protocol:
                            need_restart = True
                        if list(getattr(old_rule, 'remotes', []) or []) != list(r.remotes or []):
                            need_restart = True
                        if int(getattr(old_rule, 'qos_bandwidth_kbps', 0) or 0) != int(r.qos_bandwidth_kbps or 0):
                            need_restart = True
                        if int(getattr(old_rule, 'qos_max_conns', 0) or 0) != int(r.qos_max_conns or 0):
                            need_restart = True
                        if int(getattr(old_rule, 'qos_conn_rate', 0) or 0) != int(r.qos_conn_rate or 0):
                            need_restart = True
                        if list(getattr(old_rule, 'acl_allow_sources', []) or []) != list(r.acl_allow_sources or []):
                            need_restart = True
                        if list(getattr(old_rule, 'acl_deny_sources', []) or []) != list(r.acl_deny_sources or []):
                            need_restart = True
                        if list(getattr(old_rule, 'acl_allow_hours', []) or []) != list(r.acl_allow_hours or []):
                            need_restart = True
                        if list(getattr(old_rule, 'acl_allow_tokens', []) or []) != list(r.acl_allow_tokens or []):
                            need_restart = True
                    if need_restart:
                        try:
                            curu.stop()
                        except Exception:
                            pass
                        ul = _ClientUDPListener(r, c)  # type: ignore[arg-type]
                        ul.start()
                        self._client_udp_listeners[sync_id] = ul
                    else:
                        curu.rule = r
                        curu.client = c  # type: ignore[assignment]

        for sync_id in list(self._client_tcp_listeners.keys()):
            r = rules.get(sync_id)
            ckey = str(rule_client_key.get(sync_id) or '') if r else ''
            c = self._clients.get(ckey) if ckey else None
            if (
                (r is None)
                or (r.role != 'client')
                or ('tcp' not in r.protocol)
                or (_listen_port_or_neg1(r.listen) <= 0)
                or (not bool(r.remotes))
                or (c is None)
            ):
                self._client_tcp_listeners[sync_id].stop()
                self._client_tcp_listeners.pop(sync_id, None)
        for sync_id in list(self._client_udp_listeners.keys()):
            r = rules.get(sync_id)
            ckey = str(rule_client_key.get(sync_id) or '') if r else ''
            c = self._clients.get(ckey) if ckey else None
            if (
                (r is None)
                or (r.role != 'client')
                or ('udp' not in r.protocol)
                or (_listen_port_or_neg1(r.listen) <= 0)
                or (not bool(r.remotes))
                or (c is None)
            ):
                self._client_udp_listeners[sync_id].stop()
                self._client_udp_listeners.pop(sync_id, None)

        self._client_token_index = token_index
        self._rule_client_key = rule_client_key

        self._last_rules = rules
