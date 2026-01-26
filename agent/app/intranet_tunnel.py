from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import subprocess
import threading
import time
import uuid
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


INTRA_DIR = Path(os.getenv('REALM_AGENT_INTRANET_DIR', '/etc/realm-agent/intranet'))
SERVER_KEY = INTRA_DIR / 'server.key'
SERVER_CERT = INTRA_DIR / 'server.crt'
SERVER_PEM = INTRA_DIR / 'server.pem'

LOG_FILE = INTRA_DIR / 'intranet.log'
_LOG_LOCK = threading.Lock()

DEFAULT_TUNNEL_PORT = int(os.getenv('REALM_INTRANET_TUNNEL_PORT', '18443'))
OPEN_TIMEOUT = float(os.getenv('REALM_INTRANET_OPEN_TIMEOUT', '8.0'))
TCP_BACKLOG = int(os.getenv('REALM_INTRANET_TCP_BACKLOG', '256'))
UDP_SESSION_TTL = float(os.getenv('REALM_INTRANET_UDP_TTL', '60.0'))
MAX_FRAME = int(os.getenv('REALM_INTRANET_MAX_UDP_FRAME', '65535'))

# Fallback to plaintext only when the server side has no TLS (e.g. openssl missing on A).
# Keep it enabled by default to maximize connectivity; set REALM_INTRANET_ALLOW_PLAINTEXT=0 to force TLS-only.
ALLOW_PLAINTEXT_FALLBACK = bool(int(os.getenv('REALM_INTRANET_ALLOW_PLAINTEXT', '1') or '1'))


def _log(event: str, **fields: Any) -> None:
    """Best-effort structured log for intranet tunnel.

    Writes JSONL to /etc/realm-agent/intranet/intranet.log. Never raises.
    """
    try:
        INTRA_DIR.mkdir(parents=True, exist_ok=True)
        rec = {
            'ts': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
            'event': str(event or 'event'),
        }
        for k, v in fields.items():
            try:
                json.dumps(v)
                rec[k] = v
            except Exception:
                rec[k] = str(v)
        line = json.dumps(rec, ensure_ascii=False, separators=(',', ':')) + '\n'
        with _LOG_LOCK:
            LOG_FILE.open('a', encoding='utf-8').write(line)
    except Exception:
        pass


def _now() -> float:
    return time.time()


def _json_line(obj: Dict[str, Any]) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')


def _recv_line(sock: ssl.SSLSocket, max_len: int = 65536) -> str:
    buf = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            break
        if ch == b'\n':
            break
        buf += ch
        if len(buf) >= max_len:
            break
    return buf.decode('utf-8', errors='ignore').strip()


def _safe_close(s: Any) -> None:
    try:
        s.close()
    except Exception:
        pass


def _set_tcp_keepalive(sock: socket.socket) -> None:
    """Best-effort TCP keepalive to reduce silent half-open tunnels."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Linux-specific knobs; ignore on platforms that don't have them.
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception:
        pass


def ensure_server_cert() -> None:
    """Ensure we have a self-signed cert for intranet tunnel server.

    We intentionally avoid extra Python dependencies (cryptography). If openssl is not available,
    the tunnel can still run in plaintext TCP (not recommended), but we try hard to generate.
    """
    try:
        INTRA_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        return

    if SERVER_CERT.exists() and SERVER_KEY.exists():
        return

    # Try openssl
    openssl = shutil_which('openssl')
    if not openssl:
        return
    try:
        # Generate cert+key if missing
        if not SERVER_KEY.exists() or not SERVER_CERT.exists():
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
        if SERVER_KEY.exists() and SERVER_CERT.exists():
            pem = (SERVER_KEY.read_text(encoding='utf-8') + '\n' + SERVER_CERT.read_text(encoding='utf-8')).strip() + '\n'
            SERVER_PEM.write_text(pem, encoding='utf-8')
    except Exception:
        return


def load_server_cert_pem() -> str:
    try:
        ensure_server_cert()
        return SERVER_CERT.read_text(encoding='utf-8')
    except Exception:
        return ''


def shutil_which(cmd: str) -> Optional[str]:
    # local minimal which, avoid importing shutil at module import time in agent
    try:
        import shutil
        return shutil.which(cmd)
    except Exception:
        return None


def _mk_server_ssl_context() -> Optional[ssl.SSLContext]:
    ensure_server_cert()
    if not SERVER_CERT.exists() or not SERVER_KEY.exists():
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # prefer modern settings; Python defaults are OK.
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_COMPRESSION
        ctx.load_cert_chain(certfile=str(SERVER_CERT), keyfile=str(SERVER_KEY))
        return ctx
    except Exception:
        return None


def _mk_client_ssl_context(server_cert_pem: str | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.options |= ssl.OP_NO_SSLv2
    ctx.options |= ssl.OP_NO_SSLv3
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.check_hostname = False
    if server_cert_pem:
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.load_verify_locations(cadata=server_cert_pem)
        except Exception:
            # fallback to insecure if invalid
            ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


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


@dataclass
class ClientRuntimeState:
    key: str
    peer_host: str
    peer_port: int
    token: str
    tls_verify: bool
    connected: bool = False
    last_connect_at: float = 0.0
    last_hello_at: float = 0.0
    last_error: str = ''
    last_dial_mode: str = ''  # tls/plain


class _ControlSession:
    def __init__(self, token: str, node_id: int, sock: ssl.SSLSocket):
        self.token = token
        self.node_id = node_id
        self.sock = sock
        self.lock = threading.Lock()
        self.closed = False
        self.last_seen = _now()

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

    def close(self) -> None:
        self.closed = True
        _safe_close(self.sock)


class _TunnelServer:
    """A-side tunnel server listening on TCP/TLS port (default 18443).

    Accepts both control connections (type=hello) and data connections (type=data/data_udp).
    """

    def __init__(self, port: int):
        self.port = port
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._ssl_ctx = _mk_server_ssl_context()

        self._allowed_tokens_lock = threading.Lock()
        self._allowed_tokens: set[str] = set()

        self._sessions_lock = threading.Lock()
        self._sessions: Dict[str, _ControlSession] = {}  # token -> session

        self._pending_lock = threading.Lock()
        self._pending: Dict[Tuple[str, str], Dict[str, Any]] = {}  # (token, conn_id) -> {event, client_sock, proto, udp_sender}

    def set_allowed_tokens(self, tokens: set[str]) -> None:
        with self._allowed_tokens_lock:
            self._allowed_tokens = set(tokens)
        # drop sessions not allowed
        with self._sessions_lock:
            for t in list(self._sessions.keys()):
                if t not in tokens:
                    self._sessions[t].close()
                    self._sessions.pop(t, None)

    def get_session(self, token: str) -> Optional[_ControlSession]:
        with self._sessions_lock:
            s = self._sessions.get(token)
        if s and not s.closed:
            return s
        return None

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        th = threading.Thread(target=self._serve, name=f'intranet-tunnel:{self.port}', daemon=True)
        th.start()
        self._th = th

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        with self._sessions_lock:
            for s in self._sessions.values():
                s.close()
            self._sessions.clear()

    def _wrap(self, conn: socket.socket) -> Optional[ssl.SSLSocket]:
        """Wrap with TLS if possible.

        Important: In the wild, mismatched TLS/plaintext is the #1 reason tunnels “look ok” but never connect.
        We support a tolerant mode:
        - If TLS context is available, we *detect* whether the peer speaks TLS by peeking the first byte.
        - If peer is not TLS, we accept plaintext when REALM_INTRANET_ALLOW_PLAINTEXT=1.
        This makes deployments far more robust (especially behind reverse proxies / stripped TLS ports).
        """
        if self._ssl_ctx is None:
            return conn  # type: ignore

        # Detect TLS handshake record (0x16) / SSLv2 compatible hello (0x80).
        first = b''
        try:
            first = conn.recv(1, socket.MSG_PEEK)
        except Exception:
            first = b''

        is_tls = bool(first and first[:1] in (b'\x16', b'\x80'))
        if not is_tls:
            if ALLOW_PLAINTEXT_FALLBACK:
                return conn  # type: ignore
            _safe_close(conn)
            return None

        try:
            return self._ssl_ctx.wrap_socket(conn, server_side=True)
        except Exception as exc:
            _log('server_tls_wrap_failed', port=self.port, err=str(exc))
            if ALLOW_PLAINTEXT_FALLBACK:
                # last resort: accept as plaintext
                return conn  # type: ignore
            _safe_close(conn)
            return None

    def _serve(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', int(self.port)))
        s.listen(TCP_BACKLOG)
        s.settimeout(1.0)
        self._sock = s
        while not self._stop.is_set():
            try:
                conn, _addr = s.accept()
            except socket.timeout:
                continue
            except Exception:
                continue
            th = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            th.start()

    def _handle_conn(self, conn: socket.socket) -> None:
        _set_tcp_keepalive(conn)
        ss = self._wrap(conn)
        if ss is None:
            return
        try:
            line = _recv_line(ss)
            if not line:
                _safe_close(ss)
                return
            msg = json.loads(line)
        except Exception:
            _safe_close(ss)
            return

        mtype = str(msg.get('type') or '')
        if mtype == 'hello':
            self._handle_control(ss, msg)
            return
        if mtype in ('data', 'data_udp'):
            self._handle_data(ss, msg)
            return
        _safe_close(ss)

    def _token_allowed(self, token: str) -> bool:
        with self._allowed_tokens_lock:
            return token in self._allowed_tokens if self._allowed_tokens else True

    def _handle_control(self, ss: ssl.SSLSocket, hello: Dict[str, Any]) -> None:
        token = str(hello.get('token') or '')
        try:
            node_id = int(hello.get('node_id') or 0)
        except Exception:
            node_id = 0
        if not token or not self._token_allowed(token):
            try:
                ss.sendall(_json_line({'type': 'hello_err', 'error': 'token_invalid'}))
            except Exception:
                pass
            _safe_close(ss)
            return

        sess = _ControlSession(token=token, node_id=node_id, sock=ss)
        with self._sessions_lock:
            old = self._sessions.get(token)
            if old:
                old.close()
            self._sessions[token] = sess

        _log('control_connected', port=self.port, token=_mask_token(token), node_id=node_id)

        try:
            sess.send({'type': 'hello_ok'})
        except Exception:
            sess.close()
            return

        # Keep reading to detect disconnect; also handle optional ping.
        while not self._stop.is_set() and not sess.closed:
            try:
                line = _recv_line(ss)
                if not line:
                    break
                msg = json.loads(line)
                t = str(msg.get('type') or '')
                sess.last_seen = _now()
                if t == 'ping':
                    sess.send({'type': 'pong', 'ts': int(_now())})
            except Exception:
                break

        sess.close()
        _log('control_disconnected', port=self.port, token=_mask_token(token), node_id=node_id)
        with self._sessions_lock:
            if self._sessions.get(token) is sess:
                self._sessions.pop(token, None)

    def _handle_data(self, ss: ssl.SSLSocket, msg: Dict[str, Any]) -> None:
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


class _TCPListener:
    def __init__(self, rule: IntranetRule, tunnel: _TunnelServer):
        self.rule = rule
        self.tunnel = tunnel
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._rr = -1

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

    def _choose_target(self) -> str:
        rs = self.rule.remotes or []
        if not rs:
            return ''
        # roundrobin (fix off-by-one)
        self._rr = (self._rr + 1) % len(rs)
        return rs[self._rr]

    def _serve(self) -> None:
        host, port = _split_hostport(self.rule.listen)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(TCP_BACKLOG)
        s.settimeout(1.0)
        self._sock = s
        while not self._stop.is_set():
            try:
                c, _addr = s.accept()
            except socket.timeout:
                continue
            except Exception:
                continue
            th = threading.Thread(target=self._handle_client, args=(c,), daemon=True)
            th.start()

    def _handle_client(self, client: socket.socket) -> None:
        _set_tcp_keepalive(client)
        token = self.rule.token
        sess = self.tunnel.get_session(token)
        if not sess:
            _safe_close(client)
            return
        target = self._choose_target()
        if not target:
            _safe_close(client)
            return

        conn_id = uuid.uuid4().hex
        ev = threading.Event()
        pend = {'event': ev, 'client_sock': client, 'proto': 'tcp'}
        self.tunnel.register_pending(token, conn_id, pend)

        # ask B to open
        sess.send({'type': 'open', 'conn_id': conn_id, 'proto': 'tcp', 'target': target})

        if not ev.wait(timeout=OPEN_TIMEOUT):
            self.tunnel.pop_pending(token, conn_id)
            _safe_close(client)
            return

        pend2 = self.tunnel.pop_pending(token, conn_id) or pend
        data_sock = pend2.get('data_sock')
        ok = bool(pend2.get('ok', True))
        if not ok or not data_sock:
            _safe_close(client)
            _safe_close(data_sock)
            return

        # relay
        _relay_tcp(client, data_sock)


class _UDPSession:
    def __init__(self, udp_sock: socket.socket, client_addr: Tuple[str, int], token: str, tunnel: _TunnelServer, target: str):
        self.udp_sock = udp_sock
        self.client_addr = client_addr
        self.token = token
        self.tunnel = tunnel
        self.target = target
        self.conn_id = uuid.uuid4().hex
        self.data_sock: Optional[ssl.SSLSocket] = None
        self.ok = False
        self.last_seen = _now()
        self._send_lock = threading.Lock()
        self._rx_th: Optional[threading.Thread] = None

    def open(self) -> bool:
        sess = self.tunnel.get_session(self.token)
        if not sess:
            return False
        ev = threading.Event()
        pend = {'event': ev, 'proto': 'udp'}
        self.tunnel.register_pending(self.token, self.conn_id, pend)
        sess.send({'type': 'open', 'conn_id': self.conn_id, 'proto': 'udp', 'target': self.target})
        if not ev.wait(timeout=OPEN_TIMEOUT):
            self.tunnel.pop_pending(self.token, self.conn_id)
            return False
        pend2 = self.tunnel.pop_pending(self.token, self.conn_id) or pend
        self.data_sock = pend2.get('data_sock')
        self.ok = bool(pend2.get('ok', True)) and self.data_sock is not None
        if not self.ok:
            _safe_close(self.data_sock)
            self.data_sock = None
            return False

        th = threading.Thread(target=self._rx_loop, name='intranet-udp-rx', daemon=True)
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
                self.data_sock.sendall(frame)
        except Exception:
            _safe_close(self.data_sock)
            self.data_sock = None

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
                self.udp_sock.sendto(data, self.client_addr)
        except Exception:
            pass
        _safe_close(ds)
        self.data_sock = None

    def close(self) -> None:
        _safe_close(self.data_sock)
        self.data_sock = None


class _UDPListener:
    def __init__(self, rule: IntranetRule, tunnel: _TunnelServer):
        self.rule = rule
        self.tunnel = tunnel
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._sessions: Dict[Tuple[str, int], _UDPSession] = {}
        self._lock = threading.Lock()
        self._rr = -1

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

    def _choose_target(self) -> str:
        rs = self.rule.remotes or []
        if not rs:
            return ''
        self._rr = (self._rr + 1) % len(rs)
        return rs[self._rr]

    def _serve(self) -> None:
        host, port = _split_hostport(self.rule.listen)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.settimeout(1.0)
        self._sock = s

        # cleanup thread
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
            with self._lock:
                sess = self._sessions.get(addr)
            if not sess or not sess.ok or sess.data_sock is None:
                target = self._choose_target()
                if not target:
                    continue
                sess = _UDPSession(udp_sock=s, client_addr=addr, token=self.rule.token, tunnel=self.tunnel, target=target)
                if not sess.open():
                    continue
                with self._lock:
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


class _TunnelClient:
    """B-side client maintaining control connection to A, and opening data connections on demand."""

    def __init__(self, key: str, peer_host: str, peer_port: int, token: str, node_id: int, server_cert_pem: str = ''):
        self.key = str(key or '').strip() or f"{peer_host}:{peer_port}:{_mask_token(token)}"
        self.peer_host = peer_host
        self.peer_port = int(peer_port)
        self.token = token
        self.node_id = int(node_id)
        self.server_cert_pem = server_cert_pem or ''
        self.state = ClientRuntimeState(
            key=self.key,
            peer_host=self.peer_host,
            peer_port=self.peer_port,
            token=_mask_token(self.token),
            tls_verify=bool(self.server_cert_pem),
        )
        self._stop = threading.Event()
        self._th: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._th and self._th.is_alive():
            return
        self._stop.clear()
        th = threading.Thread(target=self._loop, name=f'intranet-client:{self.peer_host}:{self.peer_port}', daemon=True)
        th.start()
        self._th = th

    def stop(self) -> None:
        self._stop.set()

    def _dial(self) -> Optional[Any]:
        """Dial A side tunnel port.

        Prefer TLS. If A cannot enable TLS (e.g. missing openssl and no cert provisioned),
        the TLS handshake usually fails with WRONG_VERSION_NUMBER/UNKNOWN_PROTOCOL.
        In that case, and only when verification is not required, we fall back to plaintext
        to keep connectivity (still authenticated by token).
        """
        need_verify = bool(self.server_cert_pem)

        # 1) Prefer TLS
        try:
            raw = socket.create_connection((self.peer_host, self.peer_port), timeout=6)
            _set_tcp_keepalive(raw)
            ctx = _mk_client_ssl_context(self.server_cert_pem or None)
            ss = ctx.wrap_socket(raw, server_hostname=None)
            ss.settimeout(None)
            self.state.last_dial_mode = 'tls'
            return ss
        except Exception as exc:
            # 2) Fallback to plaintext: only when verification is not required and explicitly allowed.
            if need_verify or (not ALLOW_PLAINTEXT_FALLBACK):
                self.state.last_error = f"dial_tls_failed: {exc}"
                return None
            try:
                raw = socket.create_connection((self.peer_host, self.peer_port), timeout=6)
                _set_tcp_keepalive(raw)
                raw.settimeout(None)
                self.state.last_dial_mode = 'plain'
                return raw
            except Exception as exc2:
                self.state.last_error = f"dial_failed: {exc2}"
                return None

    def _loop(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            ss = self._dial()
            if not ss:
                time.sleep(min(10.0, backoff))
                backoff = min(10.0, backoff * 1.6 + 0.2)
                continue
            backoff = 1.0
            self.state.last_connect_at = _now()
            self.state.connected = False
            try:
                ss.sendall(_json_line({'type': 'hello', 'ver': 2, 'node_id': self.node_id, 'token': self.token}))
                line = _recv_line(ss)
                if not line:
                    _safe_close(ss)
                    continue
                resp = json.loads(line)
                if str(resp.get('type')) != 'hello_ok':
                    self.state.last_error = str(resp.get('error') or 'hello_failed')
                    _safe_close(ss)
                    continue
            except Exception:
                self.state.last_error = 'hello_io_failed'
                _safe_close(ss)
                continue

            self.state.connected = True
            self.state.last_hello_at = _now()
            self.state.last_error = ''
            _log('client_connected', key=self.key, peer=f"{self.peer_host}:{self.peer_port}", mode=self.state.last_dial_mode)

            # main loop
            last_ping = _now()
            while not self._stop.is_set():
                # send keepalive ping
                if _now() - last_ping > 20:
                    try:
                        ss.sendall(_json_line({'type': 'ping', 'ts': int(_now())}))
                    except Exception:
                        break
                    last_ping = _now()

                try:
                    ss.settimeout(2.0)
                    line = _recv_line(ss)
                    ss.settimeout(None)
                except socket.timeout:
                    continue
                except Exception:
                    break
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except Exception:
                    continue
                if str(msg.get('type')) == 'open':
                    threading.Thread(target=self._handle_open, args=(msg,), daemon=True).start()
            _safe_close(ss)
            if self.state.connected:
                _log('client_disconnected', key=self.key, peer=f"{self.peer_host}:{self.peer_port}")
            self.state.connected = False

    def _open_data(self) -> Optional[Any]:
        return self._dial()

    def _handle_open(self, msg: Dict[str, Any]) -> None:
        conn_id = str(msg.get('conn_id') or '')
        proto = str(msg.get('proto') or 'tcp').lower()
        target = str(msg.get('target') or '')
        if not conn_id or not target:
            return
        if proto == 'udp':
            self._handle_udp(conn_id, target)
        else:
            self._handle_tcp(conn_id, target)

    def _handle_tcp(self, conn_id: str, target: str) -> None:
        try:
            host, port = _split_hostport(target)
            out = socket.create_connection((host, port), timeout=6)
            _set_tcp_keepalive(out)
            out.settimeout(None)
        except Exception as exc:
            ds = self._open_data()
            if ds:
                try:
                    ds.sendall(_json_line({'type': 'data', 'proto': 'tcp', 'token': self.token, 'conn_id': conn_id, 'ok': False, 'error': str(exc)}))
                except Exception:
                    pass
                _safe_close(ds)
            return

        ds = self._open_data()
        if not ds:
            _safe_close(out)
            return
        try:
            ds.sendall(_json_line({'type': 'data', 'proto': 'tcp', 'token': self.token, 'conn_id': conn_id, 'ok': True}))
        except Exception:
            _safe_close(ds)
            _safe_close(out)
            return
        _relay_tcp(out, ds)

    def _handle_udp(self, conn_id: str, target: str) -> None:
        try:
            host, port = _split_hostport(target)
            us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            us.connect((host, port))
            us.settimeout(1.0)
        except Exception as exc:
            ds = self._open_data()
            if ds:
                try:
                    ds.sendall(_json_line({'type': 'data_udp', 'proto': 'udp', 'token': self.token, 'conn_id': conn_id, 'ok': False, 'error': str(exc)}))
                except Exception:
                    pass
                _safe_close(ds)
            return

        ds = self._open_data()
        if not ds:
            _safe_close(us)
            return
        try:
            ds.sendall(_json_line({'type': 'data_udp', 'proto': 'udp', 'token': self.token, 'conn_id': conn_id, 'ok': True}))
        except Exception:
            _safe_close(ds)
            _safe_close(us)
            return

        # Start bidirectional udp frame relay
        stop = threading.Event()
        threading.Thread(target=_udp_from_data_to_target, args=(ds, us, stop), daemon=True).start()
        threading.Thread(target=_udp_from_target_to_data, args=(ds, us, stop), daemon=True).start()
        # wait until closed
        while not stop.is_set():
            time.sleep(0.5)
        _safe_close(ds)
        _safe_close(us)


def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b''
        buf += chunk
    return buf


def _relay_tcp(a: socket.socket, b: ssl.SSLSocket) -> None:
    """Bidirectional relay between a plain TCP socket and a (TLS) tunnel socket."""
    stop = threading.Event()

    def _pump(src, dst):
        try:
            while not stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        stop.set()

    t1 = threading.Thread(target=_pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=_pump, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    # wait
    while not stop.is_set():
        time.sleep(0.2)
    _safe_close(a)
    _safe_close(b)


def _udp_from_data_to_target(data_sock: ssl.SSLSocket, udp_sock: socket.socket, stop: threading.Event) -> None:
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


def _udp_from_target_to_data(data_sock: ssl.SSLSocket, udp_sock: socket.socket, stop: threading.Event) -> None:
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
    addr = (addr or '').strip()
    if not addr:
        return ('', 0)
    if addr.startswith('[') and ']' in addr:
        host = addr.split(']')[0][1:]
        port = int(addr.split(']:', 1)[1])
        return (host, port)
    if addr.count(':') == 1:
        host, p = addr.split(':', 1)
        return (host.strip() or '0.0.0.0', int(p))
    # last colon
    host, p = addr.rsplit(':', 1)
    return (host.strip() or '0.0.0.0', int(p))


def _mask_token(token: str) -> str:
    t = (token or '').strip()
    if not t:
        return ''
    if len(t) <= 12:
        return t
    return f"{t[:4]}…{t[-4:]}"


class IntranetManager:
    """Supervise intranet tunnels based on pool_full.json endpoints."""

    def __init__(self, node_id: int):
        self.node_id = int(node_id)
        self._lock = threading.Lock()
        self._servers: Dict[int, _TunnelServer] = {}
        self._tcp_listeners: Dict[str, _TCPListener] = {}  # sync_id -> listener
        self._udp_listeners: Dict[str, _UDPListener] = {}
        self._clients: Dict[str, _TunnelClient] = {}  # key -> client
        self._last_rules: Dict[str, IntranetRule] = {}

    def apply_from_pool(self, pool: Dict[str, Any]) -> None:
        rules = self._parse_rules(pool)
        with self._lock:
            self._apply_rules_locked(rules)

    def status(self) -> Dict[str, Any]:
        """Lightweight runtime status for debugging."""
        with self._lock:
            servers: List[Dict[str, Any]] = []
            for p, s in self._servers.items():
                tls_on = bool(getattr(s, '_ssl_ctx', None) is not None)
                sess_map: Dict[str, Any] = getattr(s, '_sessions', {})  # token -> _ControlSession
                sessions = []
                try:
                    for t, sess in list(sess_map.items()):
                        sessions.append({
                            'token': _mask_token(t),
                            'node_id': int(getattr(sess, 'node_id', 0) or 0),
                            'last_seen': int(getattr(sess, 'last_seen', 0) or 0),
                        })
                except Exception:
                    sessions = [_mask_token(x) for x in list(sess_map.keys())]
                servers.append({'port': p, 'tls': tls_on, 'sessions': sessions})

            clients = []
            for k, c in self._clients.items():
                st = getattr(c, 'state', None)
                if isinstance(st, ClientRuntimeState):
                    clients.append({
                        'key': k,
                        'peer': f"{st.peer_host}:{st.peer_port}",
                        'token': st.token,
                        'tls_verify': bool(st.tls_verify),
                        'connected': bool(st.connected),
                        'dial_mode': st.last_dial_mode,
                        'last_connect': int(st.last_connect_at),
                        'last_hello': int(st.last_hello_at),
                        'last_error': st.last_error,
                    })
                else:
                    clients.append({'key': k})

            # shrink rule snapshot: avoid sending large PEMs in frequent push reports
            def rule_view(r: IntranetRule) -> Dict[str, Any]:
                return {
                    'sync_id': r.sync_id,
                    'role': r.role,
                    'listen': r.listen,
                    'protocol': r.protocol,
                    'balance': r.balance,
                    'remotes': r.remotes,
                    'peer_node_id': r.peer_node_id,
                    'peer_host': r.peer_host,
                    'tunnel_port': r.tunnel_port,
                    'token': _mask_token(r.token),
                    'tls_verify': bool(r.server_cert_pem),
                }

            return {
                'servers': servers,
                'tcp_rules': list(self._tcp_listeners.keys()),
                'udp_rules': list(self._udp_listeners.keys()),
                'clients': clients,
                'rules': {k: rule_view(v) for k, v in self._last_rules.items()},
            }

    def diagnose(self) -> Dict[str, Any]:
        """High-level diagnosis: highlights the most common misconfigurations."""
        st = self.status()
        warnings: List[str] = []
        rules: Dict[str, Any] = st.get('rules') or {}

        # server rules should have matching client connected
        try:
            for sync_id, r in rules.items():
                role = str(r.get('role') or '')
                token_mask = str(r.get('token') or '')
                if role == 'server':
                    port = int(r.get('tunnel_port') or DEFAULT_TUNNEL_PORT)
                    found = False
                    for srv in st.get('servers') or []:
                        if int(srv.get('port') or 0) != port:
                            continue
                        for s in srv.get('sessions') or []:
                            tok = s.get('token') if isinstance(s, dict) else str(s)
                            if tok and (token_mask == tok):
                                found = True
                                break
                        if found:
                            break
                    if not found:
                        warnings.append(f"[server] 规则 {sync_id} 未检测到内网客户端连接（token={token_mask}，port={port}）。")
                elif role == 'client':
                    peer = str(r.get('peer_host') or '')
                    port = int(r.get('tunnel_port') or DEFAULT_TUNNEL_PORT)
                    found_client = False
                    for c in st.get('clients') or []:
                        if not isinstance(c, dict):
                            continue
                        k = str(c.get('key') or '')
                        # key contains peer:port:token (raw or masked). We match loosely by peer/port.
                        if (peer and peer in k and str(port) in k):
                            found_client = True
                            if not bool(c.get('connected')):
                                warnings.append(f"[client] 规则 {sync_id} 客户端未连接到 {peer}:{port}（{c.get('last_error') or 'no_error'}）。")
                            break
                    if not found_client:
                        warnings.append(f"[client] 规则 {sync_id} 未启动客户端（peer={peer}:{port}）。")
        except Exception:
            pass

        return {
            'ok': True,
            'status': st,
            'warnings': warnings,
        }

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
            role = str(ex.get('intranet_role') or '').strip()
            if role not in ('server', 'client'):
                continue
            sync_id = str(ex.get('sync_id') or '').strip() or uuid.uuid4().hex
            listen = str(e.get('listen') or '').strip()
            protocol = str(e.get('protocol') or 'tcp+udp').strip().lower() or 'tcp+udp'
            balance = str(e.get('balance') or 'roundrobin').strip() or 'roundrobin'
            remotes: List[str] = []
            if isinstance(e.get('remotes'), list):
                remotes = [str(x).strip() for x in e.get('remotes') if str(x).strip()]
            elif isinstance(e.get('remote'), str) and e.get('remote'):
                remotes = [str(e.get('remote')).strip()]
            token = str(ex.get('intranet_token') or '').strip()
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
            )
        return out

    def _apply_rules_locked(self, rules: Dict[str, IntranetRule]) -> None:
        # servers: collect tokens per port
        tokens_by_port: Dict[int, set[str]] = {}
        for r in rules.values():
            if r.role == 'server':
                tokens_by_port.setdefault(r.tunnel_port, set()).add(r.token)

        # start/stop servers
        for port, tokens in tokens_by_port.items():
            srv = self._servers.get(port)
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
        for sync_id, r in rules.items():
            if r.role != 'server':
                continue
            srv = self._servers.get(r.tunnel_port)
            if not srv:
                continue
            if 'tcp' in r.protocol:
                if sync_id not in self._tcp_listeners:
                    lis = _TCPListener(r, srv)
                    lis.start()
                    self._tcp_listeners[sync_id] = lis
            else:
                if sync_id in self._tcp_listeners:
                    self._tcp_listeners[sync_id].stop()
                    self._tcp_listeners.pop(sync_id, None)

            if 'udp' in r.protocol:
                if sync_id not in self._udp_listeners:
                    ul = _UDPListener(r, srv)
                    ul.start()
                    self._udp_listeners[sync_id] = ul
            else:
                if sync_id in self._udp_listeners:
                    self._udp_listeners[sync_id].stop()
                    self._udp_listeners.pop(sync_id, None)

        # stop removed listeners
        for sync_id in list(self._tcp_listeners.keys()):
            if sync_id not in rules or rules[sync_id].role != 'server' or ('tcp' not in rules[sync_id].protocol):
                self._tcp_listeners[sync_id].stop()
                self._tcp_listeners.pop(sync_id, None)
        for sync_id in list(self._udp_listeners.keys()):
            if sync_id not in rules or rules[sync_id].role != 'server' or ('udp' not in rules[sync_id].protocol):
                self._udp_listeners[sync_id].stop()
                self._udp_listeners.pop(sync_id, None)

        # clients on client role
        desired_clients: Dict[str, _TunnelClient] = {}
        for r in rules.values():
            if r.role != 'client':
                continue
            key = f"{r.peer_host}:{r.tunnel_port}:{r.token}"
            c = self._clients.get(key)
            if not c:
                c = _TunnelClient(key=key, peer_host=r.peer_host, peer_port=r.tunnel_port, token=r.token, node_id=self.node_id, server_cert_pem=r.server_cert_pem)
                c.start()
            desired_clients[key] = c
        # stop removed
        for key in list(self._clients.keys()):
            if key not in desired_clients:
                self._clients[key].stop()
                self._clients.pop(key, None)

        self._last_rules = rules
