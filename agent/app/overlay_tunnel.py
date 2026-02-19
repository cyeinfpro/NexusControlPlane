import os
import socket
import threading
import time
import select
import ipaddress
from typing import Any, Dict, List, Optional, Tuple


def _now_ts() -> float:
    return time.time()


def _safe_close(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


def _parse_host_port(addr: str) -> Tuple[str, Optional[int]]:
    s = str(addr or "").strip()
    if not s:
        return "", None

    # [IPv6]:port
    if s.startswith("["):
        r = s.rfind("]")
        if r > 0:
            host = s[1:r]
            rest = s[r + 1 :].strip()
            if rest.startswith(":"):
                rest = rest[1:]
            try:
                p = int(rest)
            except Exception:
                p = None
            return host, p

    # host:port (IPv4/hostname)
    if ":" in s and s.count(":") == 1:
        h, p0 = s.split(":", 1)
        h = h.strip()
        try:
            p = int(p0.strip())
        except Exception:
            p = None
        return h, p

    # IPv6 without brackets is ambiguous; treat as host-only
    return s, None


def _format_host_port(host: str, port: int) -> str:
    h = str(host or "").strip() or "0.0.0.0"
    p = int(port)
    if ":" in h and not h.startswith("["):
        return f"[{h}]:{p}"
    return f"{h}:{p}"




def _normalize_dest(addr: str) -> Tuple[str, Optional[int], str]:
    """Normalize a destination string to a canonical host:port.

    Returns (host, port, normalized_str). host is lowercased when it looks like a hostname.
    """
    host, port = _parse_host_port(addr)
    if not host or port is None:
        return "", None, ""
    h = str(host).strip()
    p = int(port)

    # Lowercase hostname for stable comparisons; keep IP literals unchanged.
    core = h.split('%', 1)[0]
    try:
        ipaddress.ip_address(core)
        is_ip = True
    except Exception:
        is_ip = False
    if not is_ip:
        h = h.lower()

    return h, p, _format_host_port(h, p)
def _readline(sock: socket.socket, limit: int = 512) -> bytes:
    buf = bytearray()
    while len(buf) < limit:
        b = sock.recv(1)
        if not b:
            break
        buf += b
        if b == b"\n":
            break
    return bytes(buf)


def _relay_bidirectional(a: socket.socket, b: socket.socket, stop_evt: Optional[threading.Event] = None) -> None:
    """Relay bytes between sockets a and b until EOF/error/stop.

    NOTE: Must flush buffered data even after one side half-closes, otherwise small
    request/response flows may lose tail bytes.
    """

    stop_evt = stop_evt or threading.Event()
    try:
        a.setblocking(False)
    except Exception:
        pass
    try:
        b.setblocking(False)
    except Exception:
        pass

    buf_ab = bytearray()
    buf_ba = bytearray()
    max_buf = 1024 * 1024  # 1 MiB per direction

    a_eof = False
    b_eof = False
    a_to_b_shutdown = False
    b_to_a_shutdown = False

    while not stop_evt.is_set():
        # stop when both sides are closed and buffers are drained
        if a_eof and b_eof and (not buf_ab) and (not buf_ba):
            break

        rlist: List[socket.socket] = []
        wlist: List[socket.socket] = []

        if (not a_eof) and len(buf_ab) < max_buf:
            rlist.append(a)
        if (not b_eof) and len(buf_ba) < max_buf:
            rlist.append(b)
        if buf_ab:
            wlist.append(b)
        if buf_ba:
            wlist.append(a)

        if not rlist and not wlist:
            break

        try:
            rdy_r, rdy_w, _ = select.select(rlist, wlist, [], 1.0)
        except Exception:
            break

        # ---- read ----
        if (a in rdy_r) and (not a_eof):
            try:
                data = a.recv(16384)
            except BlockingIOError:
                data = None
            except Exception:
                break
            if data is None:
                pass
            elif data:
                buf_ab += data
            else:
                a_eof = True

        if (b in rdy_r) and (not b_eof):
            try:
                data = b.recv(16384)
            except BlockingIOError:
                data = None
            except Exception:
                break
            if data is None:
                pass
            elif data:
                buf_ba += data
            else:
                b_eof = True

        # ---- write ----
        if (b in rdy_w) and buf_ab:
            try:
                sent = b.send(buf_ab)
            except BlockingIOError:
                sent = 0
            except Exception:
                break
            if sent > 0:
                del buf_ab[:sent]

        if (a in rdy_w) and buf_ba:
            try:
                sent = a.send(buf_ba)
            except BlockingIOError:
                sent = 0
            except Exception:
                break
            if sent > 0:
                del buf_ba[:sent]

        # propagate half-close (after buffers drained)
        if a_eof and (not buf_ab) and (not a_to_b_shutdown):
            try:
                b.shutdown(socket.SHUT_WR)
            except Exception:
                pass
            a_to_b_shutdown = True

        if b_eof and (not buf_ba) and (not b_to_a_shutdown):
            try:
                a.shutdown(socket.SHUT_WR)
            except Exception:
                pass
            b_to_a_shutdown = True


class _OverlayExitServer:
    """C-side exit proxy: accepts overlay connections and forwards to dynamic targets."""

    def __init__(self, host: str, port: int):
        self.host = str(host or "127.0.0.1").strip() or "127.0.0.1"
        self.port = int(port)
        self._sock: Optional[socket.socket] = None
        self._thr: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        # sync_id -> {token:str, allowlist:set[str]}
        self._groups: Dict[str, Dict[str, Any]] = {}
        self._active = 0

    def update_groups(self, groups: Dict[str, Dict[str, Any]]) -> None:
        with self._lock:
            # normalize allowlist to canonical host:port set[str]
            out: Dict[str, Dict[str, Any]] = {}
            for sid, cfg in (groups or {}).items():
                if not sid:
                    continue
                token = str((cfg or {}).get("token") or "").strip()
                if not token:
                    continue
                allow_raw = (cfg or {}).get("allowlist")
                allow_set: set[str] = set()
                if isinstance(allow_raw, list):
                    for x in allow_raw:
                        s = str(x).strip()
                        if not s:
                            continue
                        _h, _p, norm = _normalize_dest(s)
                        if norm:
                            allow_set.add(norm)
                out[str(sid)] = {"token": token, "allowlist": allow_set}
            self._groups = out

    def start(self) -> None:
        if self._thr and self._thr.is_alive():
            return
        self._stop.clear()
        self._thr = threading.Thread(target=self._run, name=f"overlay-exit-{self.port}", daemon=True)
        self._thr.start()

    def stop(self) -> None:
        self._stop.set()
        _safe_close(self._sock)
        self._sock = None

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "host": self.host,
                "port": self.port,
                "groups": len(self._groups),
                "active": int(self._active),
            }

    def _run(self) -> None:
        try:
            addrinfos = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM, 0, socket.AI_PASSIVE)
            af, socktype, proto, _canon, sa = addrinfos[0]
            s = socket.socket(af, socktype, proto)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(sa)
                s.listen(256)
            except Exception:
                _safe_close(s)
                return
            s.settimeout(1.0)
            self._sock = s
        except Exception:
            return

        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            t = threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True)
            t.start()

        _safe_close(self._sock)
        self._sock = None

    def _handle_conn(self, conn: socket.socket, _addr: Any) -> None:
        with self._lock:
            self._active += 1
        try:
            conn.settimeout(10.0)
            line = _readline(conn, limit=512)
            if not line:
                return
            try:
                text = line.decode("utf-8", errors="ignore").strip()
            except Exception:
                return
            parts = [p for p in text.split(" ") if p]
            if len(parts) < 4 or parts[0] != "NXOV1":
                return
            sync_id = parts[1].strip()
            token = parts[2].strip()
            dest = " ".join(parts[3:]).strip()
            if not (sync_id and token and dest):
                return

            # validate
            with self._lock:
                g = dict(self._groups.get(sync_id) or {})
            if not g:
                return
            if token != str(g.get("token") or ""):
                return
            allow: set = g.get("allowlist") if isinstance(g.get("allowlist"), set) else set()
            dh, dp, dest_norm = _normalize_dest(dest)
            if not dh or dp is None or not (1 <= int(dp) <= 65535):
                return
            if allow:
                if dest_norm not in allow:
                    return

            # connect to target
            try:
                conn.settimeout(None)
            except Exception:
                pass
            try:
                upstream = socket.create_connection((dh, int(dp)), timeout=10.0)
            except Exception:
                return

            try:
                upstream.settimeout(None)
            except Exception:
                pass

            # relay both ways
            _relay_bidirectional(conn, upstream, self._stop)
        finally:
            _safe_close(conn)
            with self._lock:
                self._active = max(0, int(self._active) - 1)


class _OverlayForwardListener:
    """Client-side forwarder: listens on local port and tunnels to overlay entry (A)."""

    def __init__(
        self,
        listen: str,
        overlay_entry: str,
        overlay_sync_id: str,
        overlay_token: str,
        remotes: List[str],
        balance: str = "roundrobin",
    ):
        self.listen = str(listen or "").strip()
        self.overlay_entry = str(overlay_entry or "").strip()
        self.overlay_sync_id = str(overlay_sync_id or "").strip()
        self.overlay_token = str(overlay_token or "").strip()
        self.remotes = [str(x).strip() for x in (remotes or []) if str(x).strip()]
        self.balance = str(balance or "roundrobin").strip() or "roundrobin"

        self._sock: Optional[socket.socket] = None
        self._thr: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._rr = 0
        self._active = 0

    def key(self) -> str:
        return self.listen

    def start(self) -> None:
        if self._thr and self._thr.is_alive():
            return
        self._stop.clear()
        self._thr = threading.Thread(target=self._run, name=f"overlay-fwd-{self.listen}", daemon=True)
        self._thr.start()

    def stop(self) -> None:
        self._stop.set()
        _safe_close(self._sock)
        self._sock = None

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "listen": self.listen,
                "overlay_entry": self.overlay_entry,
                "overlay_sync_id": self.overlay_sync_id,
                "remote_count": len(self.remotes),
                "active": int(self._active),
                "balance": self.balance,
            }

    def _pick_remote(self, client_ip: str = "") -> Optional[str]:
        rems = self.remotes
        if not rems:
            return None
        if len(rems) == 1:
            return rems[0]

        algo = str(self.balance or "roundrobin").strip().lower()
        # support "algo:w1,w2,..." (only random_weight)
        weights: Optional[List[int]] = None
        if ":" in algo:
            a0, w0 = algo.split(":", 1)
            algo = a0.strip().lower()
            try:
                ww = [int(x.strip()) for x in w0.split(",") if x.strip()]
                if len(ww) == len(rems) and all(x > 0 for x in ww):
                    weights = ww
            except Exception:
                weights = None

        if algo in ("random", "random_weight"):
            if weights:
                total = sum(weights)
                r = int(_now_ts() * 1000) % max(total, 1)
                acc = 0
                for i, w in enumerate(weights):
                    acc += w
                    if r < acc:
                        return rems[i]
            # simple pseudo-random
            idx = int(_now_ts() * 1000) % len(rems)
            return rems[idx]

        if algo in ("iphash", "consistent_hash"):
            h = 0
            for ch in (client_ip or ""):
                h = (h * 131 + ord(ch)) & 0xFFFFFFFF
            return rems[h % len(rems)]

        # default: roundrobin
        with self._lock:
            idx = self._rr % len(rems)
            self._rr += 1
        return rems[idx]

    def _run(self) -> None:
        lh, lp = _parse_host_port(self.listen)
        if not lh:
            lh = "0.0.0.0"
        if lp is None:
            return
        port = int(lp)
        try:
            addrinfos = socket.getaddrinfo(lh, port, 0, socket.SOCK_STREAM, 0, socket.AI_PASSIVE)
            af, socktype, proto, _canon, sa = addrinfos[0]
            s = socket.socket(af, socktype, proto)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(sa)
                s.listen(256)
            except Exception:
                _safe_close(s)
                return
            s.settimeout(1.0)
            self._sock = s
        except Exception:
            return

        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            t = threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True)
            t.start()

        _safe_close(self._sock)
        self._sock = None

    def _handle_conn(self, conn: socket.socket, addr: Any) -> None:
        with self._lock:
            self._active += 1
        try:
            client_ip = ""
            try:
                if isinstance(addr, tuple) and len(addr) >= 1:
                    client_ip = str(addr[0] or "")
            except Exception:
                client_ip = ""

            dest = self._pick_remote(client_ip) or ""
            if not dest:
                return
            eh, ep = _parse_host_port(self.overlay_entry)
            if not eh or ep is None:
                return

            # connect to overlay entry
            try:
                upstream = socket.create_connection((eh, int(ep)), timeout=10.0)
            except Exception:
                return
            try:
                conn.settimeout(None)
                upstream.settimeout(None)
            except Exception:
                pass

            # send header
            header = f"NXOV1 {self.overlay_sync_id} {self.overlay_token} {dest}\n".encode("utf-8", errors="ignore")
            try:
                upstream.sendall(header)
            except Exception:
                _safe_close(upstream)
                return

            _relay_bidirectional(conn, upstream, self._stop)
        finally:
            _safe_close(conn)
            with self._lock:
                self._active = max(0, int(self._active) - 1)


class OverlayManager:
    """Runtime for Route B overlay.

    - Client forwarders are driven by endpoints with extra_config.forward_tool == 'overlay'.
    - Exit proxy servers are driven by MPTCP group endpoints with extra_config.mptcp_overlay_enabled
      and extra_config.mptcp_role == 'aggregator'.
    """

    def __init__(self, node_id: int = 0):
        self.node_id = int(node_id)
        raw = str(os.getenv('REALM_AGENT_DISABLE_OVERLAY', '') or '').strip().lower()
        self.disabled = raw in ('1', 'true', 'yes', 'y', 'on')
        self._lock = threading.Lock()
        self._forward: Dict[str, _OverlayForwardListener] = {}
        self._exit: Dict[Tuple[str, int], _OverlayExitServer] = {}
        self._last_apply_ts = 0.0

    def apply_from_pool(self, pool: Dict[str, Any]) -> Dict[str, Any]:
        if bool(self.disabled):
            try:
                self.stop()
            except Exception:
                pass
            return {"ok": True, "disabled": True, "forward": 0, "exit": 0}

        eps = pool.get("endpoints") if isinstance(pool, dict) else []
        if not isinstance(eps, list):
            eps = []

        # new desired configs
        desired_forward: Dict[str, Dict[str, Any]] = {}
        desired_exit: Dict[Tuple[str, int], Dict[str, Dict[str, Any]]] = {}

        for ep in eps:
            if not isinstance(ep, dict):
                continue
            ex = ep.get("extra_config") if isinstance(ep.get("extra_config"), dict) else {}
            fwd = str(ex.get("forward_tool") or ep.get("forward_tool") or "").strip().lower()

            # client-side overlay forwarders
            if fwd == "overlay":
                if bool(ep.get("disabled")):
                    continue
                listen = str(ep.get("listen") or "").strip()
                if not listen:
                    continue
                overlay_entry = str(ex.get("overlay_entry") or "").strip()
                overlay_sync_id = str(ex.get("overlay_sync_id") or "").strip()
                overlay_token = str(ex.get("overlay_token") or "").strip()
                if not (overlay_entry and overlay_sync_id and overlay_token):
                    continue
                remotes_raw = ep.get("remotes")
                remotes: List[str] = []
                if isinstance(remotes_raw, list):
                    remotes = [str(x).strip() for x in remotes_raw if str(x).strip()]
                elif isinstance(remotes_raw, str):
                    remotes = [x.strip() for x in remotes_raw.splitlines() if x.strip()]
                if not remotes:
                    # nothing to forward
                    continue
                bal = str(ep.get("balance") or "roundrobin").strip() or "roundrobin"
                key = listen
                desired_forward[key] = {
                    "listen": listen,
                    "overlay_entry": overlay_entry,
                    "overlay_sync_id": overlay_sync_id,
                    "overlay_token": overlay_token,
                    "remotes": remotes,
                    "balance": bal,
                }
                continue

            # exit proxy (aggregator role)
            role = str(ex.get("mptcp_role") or "").strip().lower()
            if role in ("aggregator", "agg", "c") and bool(ex.get("mptcp_overlay_enabled")):
                sync_id = str(ex.get("sync_id") or "").strip()
                token = str(ex.get("mptcp_overlay_token") or "").strip()
                if not (sync_id and token):
                    continue
                try:
                    exit_port = int(ex.get("mptcp_overlay_exit_port") or 0)
                except Exception:
                    exit_port = 0
                if not (1 <= exit_port <= 65535):
                    exit_port = 38444
                allow_raw = ex.get("mptcp_overlay_allowlist")
                if not isinstance(allow_raw, list):
                    allow_raw = ex.get("sync_original_remotes") if isinstance(ex.get("sync_original_remotes"), list) else []
                allowlist = [str(x).strip() for x in (allow_raw or []) if str(x).strip()]
                exit_host = str(ex.get("mptcp_overlay_exit_host") or ex.get("overlay_exit_host") or "127.0.0.1").strip() or "127.0.0.1"
                desired_exit.setdefault((exit_host, int(exit_port)), {})[sync_id] = {"token": token, "allowlist": allowlist}

        # apply changes
        with self._lock:
            self._last_apply_ts = _now_ts()

            # forward listeners: stop removed / changed
            for k in list(self._forward.keys()):
                if k not in desired_forward:
                    try:
                        self._forward[k].stop()
                    except Exception:
                        pass
                    self._forward.pop(k, None)

            for k, cfg in desired_forward.items():
                cur = self._forward.get(k)
                if cur is not None:
                    # restart if config changed
                    if (
                        cur.overlay_entry != cfg.get("overlay_entry")
                        or cur.overlay_sync_id != cfg.get("overlay_sync_id")
                        or cur.overlay_token != cfg.get("overlay_token")
                        or cur.balance != cfg.get("balance")
                        or cur.remotes != cfg.get("remotes")
                    ):
                        try:
                            cur.stop()
                        except Exception:
                            pass
                        self._forward.pop(k, None)
                        cur = None
                if cur is None:
                    try:
                        lst = _OverlayForwardListener(
                            listen=str(cfg.get("listen") or ""),
                            overlay_entry=str(cfg.get("overlay_entry") or ""),
                            overlay_sync_id=str(cfg.get("overlay_sync_id") or ""),
                            overlay_token=str(cfg.get("overlay_token") or ""),
                            remotes=list(cfg.get("remotes") or []),
                            balance=str(cfg.get("balance") or "roundrobin"),
                        )
                        lst.start()
                        self._forward[k] = lst
                    except Exception:
                        pass

            # exit servers: stop removed
            for p in list(self._exit.keys()):
                if p not in desired_exit:
                    try:
                        self._exit[p].stop()
                    except Exception:
                        pass
                    self._exit.pop(p, None)

            # create/update
            for key, groups in desired_exit.items():
                try:
                    host, port = key
                except Exception:
                    continue
                host = str(host or "127.0.0.1").strip() or "127.0.0.1"
                port = int(port)
                srv = self._exit.get((host, port))
                if srv is None:
                    try:
                        srv = _OverlayExitServer(host=host, port=port)
                        srv.update_groups(groups)
                        srv.start()
                        self._exit[(host, port)] = srv
                    except Exception:
                        continue
                else:
                    try:
                        srv.update_groups(groups)
                    except Exception:
                        pass

        return {
            "ok": True,
            "forward": len(desired_forward),
            "exit": len(desired_exit),
        }

    def status(self) -> Dict[str, Any]:
        with self._lock:
            fwd = [self._forward[k].status() for k in sorted(self._forward.keys())]
            ex = [self._exit[k].status() for k in sorted(self._exit.keys(), key=lambda x: (str(x[0]), int(x[1])))]
            return {
                "ok": True,
                "disabled": bool(self.disabled),
                "node_id": self.node_id,
                "last_apply_ts": self._last_apply_ts,
                "forward": fwd,
                "exit": ex,
            }

    def stop(self) -> None:
        with self._lock:
            for k, lst in list(self._forward.items()):
                try:
                    lst.stop()
                except Exception:
                    pass
            self._forward.clear()
            for p, srv in list(self._exit.items()):
                try:
                    srv.stop()
                except Exception:
                    pass
            self._exit.clear()
