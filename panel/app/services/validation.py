from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

from ..utils.normalize import split_host_port


class PoolValidationError(ValueError):
    """Raised when a pool (or a rule) fails validation."""


# -------------------- basic helpers --------------------

def _algo_norm(name: Any) -> str:
    s = str(name or '').strip().lower()
    s = re.sub(r'[\s_-]+', '', s)
    if not s:
        return 'roundrobin'
    if s == 'iphash':
        return 'iphash'
    if s in ('roundrobin', 'roundrobin:'):
        return 'roundrobin'
    return s


def _proto_set(protocol: Any) -> Set[str]:
    s = str(protocol or 'tcp+udp').strip().lower()
    out: Set[str] = set()
    if 'tcp' in s:
        out.add('tcp')
    if 'udp' in s:
        out.add('udp')
    if not out:
        out = {'tcp', 'udp'}
    return out


def _host_norm(host: str) -> str:
    return (host or '').strip().strip('[]').lower()


def _is_wildcard_host(host: str) -> bool:
    h = _host_norm(host)
    return h in ('', '0.0.0.0', '::', '0:0:0:0:0:0:0:0', '*')


def _hosts_overlap(a: str, b: str) -> bool:
    ha = _host_norm(a)
    hb = _host_norm(b)
    if _is_wildcard_host(ha) or _is_wildcard_host(hb):
        return True
    return ha == hb


def parse_addr(addr: Any) -> Tuple[str, int]:
    raw = str(addr or '').strip()
    if not raw:
        raise PoolValidationError('地址不能为空')
    if '://' in raw:
        try:
            u = urlparse(raw)
            host = (u.hostname or '').strip()
            port = u.port
            if host and port:
                return host, int(port)
        except Exception:
            pass
    host, port = split_host_port(raw)
    host = (host or '').strip()
    if not host or not port:
        raise PoolValidationError(f"地址格式不正确: {raw} (应为 host:port)")
    if not (1 <= int(port) <= 65535):
        raise PoolValidationError(f"端口范围不正确: {raw} (1-65535)")
    return host, int(port)


def parse_balance_weights(balance: Any) -> Tuple[str, List[int]]:
    s = str(balance or '').strip()
    if not s:
        return 'roundrobin', []
    if ':' not in s:
        return _algo_norm(s), []
    algo_raw, rest = s.split(':', 1)
    algo = _algo_norm(algo_raw)
    weights: List[int] = []
    for tok in rest.split(','):
        t = tok.strip()
        if not t:
            continue
        if not re.fullmatch(r'\d+', t):
            raise PoolValidationError(f"权重不是整数: {t}")
        w = int(t)
        if w <= 0:
            raise PoolValidationError(f"权重必须 > 0: {t}")
        weights.append(w)
    return algo, weights


def validate_weights(balance: Any, remote_count: int, *, where: str = '') -> None:
    if remote_count <= 1:
        return
    algo, weights = parse_balance_weights(balance)
    if algo == 'iphash':
        if weights:
            raise PoolValidationError(f"{where}IP Hash 不支持权重")
        return
    if weights and len(weights) != int(remote_count):
        raise PoolValidationError(f"{where}权重数量({len(weights)})必须与目标行数({int(remote_count)})一致")


def list_runtime_remotes(ep: Dict[str, Any]) -> List[str]:
    rs: List[str] = []
    if isinstance(ep.get('remote'), str) and str(ep.get('remote') or '').strip():
        rs.append(str(ep.get('remote')).strip())
    if isinstance(ep.get('remotes'), list):
        for x in ep.get('remotes') or []:
            s = str(x or '').strip()
            if s:
                rs.append(s)
    if isinstance(ep.get('extra_remotes'), list):
        for x in ep.get('extra_remotes') or []:
            s = str(x or '').strip()
            if s:
                rs.append(s)
    seen: Set[str] = set()
    out: List[str] = []
    for r in rs:
        if r in seen:
            continue
        seen.add(r)
        out.append(r)
    return out


def effective_remote_count_for_weights(ep: Dict[str, Any]) -> int:
    ex = ep.get('extra_config')
    ex = ex if isinstance(ex, dict) else {}
    if str(ex.get('sync_role') or '') == 'sender' and isinstance(ex.get('sync_original_remotes'), list):
        orig = [str(x or '').strip() for x in (ex.get('sync_original_remotes') or [])]
        orig = [x for x in orig if x]
        if orig:
            return len(orig)
    return len(list_runtime_remotes(ep))


def endpoint_binds_listen(ep: Dict[str, Any]) -> bool:
    if bool(ep.get('disabled', False)):
        return False
    ex = ep.get('extra_config')
    ex = ex if isinstance(ex, dict) else {}
    if str(ex.get('intranet_role') or '') == 'client':
        return False
    return True


@dataclass
class _Binding:
    kind: str
    port: int
    host: str
    protos: Set[str]
    listen: str
    remark: str = ''
    idx: Optional[int] = None


def _binding_label(b: _Binding) -> str:
    rem = f"（备注: {b.remark}）" if b.remark else ''
    if b.kind == 'intranet_tunnel':
        return f"内网穿透隧道端口 {b.port}{rem}"
    return f"{b.listen}{rem}"


def validate_pool(pool: Dict[str, Any]) -> None:
    eps = pool.get('endpoints') or []
    if not isinstance(eps, list):
        raise PoolValidationError('pool.endpoints 必须为数组')
    for i, ep in enumerate(eps):
        if not isinstance(ep, dict):
            continue
        if bool(ep.get('disabled', False)):
            continue
        ex = ep.get('extra_config')
        ex = ex if isinstance(ex, dict) else {}
        intranet_role = str(ex.get('intranet_role') or '').strip()
        if endpoint_binds_listen(ep):
            listen = str(ep.get('listen') or '').strip()
            host, port = split_host_port(listen)
            if not port:
                raise PoolValidationError(f"第 {i+1} 条规则 listen 格式不正确: {listen}")
            if not (1 <= int(port) <= 65535):
                raise PoolValidationError(f"第 {i+1} 条规则 listen 端口范围不正确: {listen} (1-65535)")
        if intranet_role != 'client':
            remotes = list_runtime_remotes(ep)
            if not remotes:
                raise PoolValidationError(f"第 {i+1} 条规则目标地址不能为空")
            for r in remotes:
                try:
                    parse_addr(r)
                except PoolValidationError as exc:
                    raise PoolValidationError(f"第 {i+1} 条规则目标地址无效: {exc}")
        n = effective_remote_count_for_weights(ep)
        validate_weights(ep.get('balance'), n, where=f"第 {i+1} 条规则")
    bindings: List[_Binding] = []
    for idx, ep in enumerate(eps):
        if not isinstance(ep, dict):
            continue
        if not endpoint_binds_listen(ep):
            continue
        listen = str(ep.get('listen') or '').strip()
        host, port = split_host_port(listen)
        if not port or int(port) <= 0:
            continue
        remark = str(ep.get('remark') or '').strip()
        bindings.append(_Binding('endpoint', int(port), str(host or '').strip(), _proto_set(ep.get('protocol')), listen, remark, idx))
    tunnel_ports: Set[int] = set()
    for ep in eps:
        if not isinstance(ep, dict) or bool(ep.get('disabled', False)):
            continue
        ex = ep.get('extra_config')
        ex = ex if isinstance(ex, dict) else {}
        if str(ex.get('intranet_role') or '') != 'server':
            continue
        try:
            p = int(ex.get('intranet_server_port') or 0)
        except Exception:
            p = 0
        if p <= 0:
            continue
        if not (1 <= p <= 65535):
            raise PoolValidationError(f"内网穿透隧道端口范围不正确: {p} (1-65535)")
        tunnel_ports.add(p)
    for p in sorted(tunnel_ports):
        bindings.append(_Binding('intranet_tunnel', int(p), '0.0.0.0', {'tcp'}, f"0.0.0.0:{int(p)}"))
    by_port: Dict[int, List[_Binding]] = {}
    for b in bindings:
        by_port.setdefault(int(b.port), []).append(b)
    for port, items in by_port.items():
        if len(items) <= 1:
            continue
        for i in range(len(items)):
            a = items[i]
            for j in range(i + 1, len(items)):
                b = items[j]
                if not _hosts_overlap(a.host, b.host):
                    continue
                common = a.protos & b.protos
                if not common:
                    continue
                common_txt = '/'.join(sorted(common)).upper()
                raise PoolValidationError(f"端口冲突（{common_txt}）：{_binding_label(a)} 与 {_binding_label(b)} 同时启用会冲突")


def find_listen_conflict(pool: Dict[str, Any], listen: str, protocol: Any, *, ignore_sync_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    listen = str(listen or '').strip()
    host, port = split_host_port(listen)
    if not port:
        raise PoolValidationError(f"listen 格式不正确: {listen}")
    if not (1 <= int(port) <= 65535):
        raise PoolValidationError(f"listen 端口范围不正确: {listen} (1-65535)")
    cand_host = str(host or '').strip()
    cand_port = int(port)
    cand_proto = _proto_set(protocol)
    eps = pool.get('endpoints') or []
    if not isinstance(eps, list):
        eps = []
    for ep in eps:
        if not isinstance(ep, dict) or bool(ep.get('disabled', False)):
            continue
        ex = ep.get('extra_config')
        ex = ex if isinstance(ex, dict) else {}
        sid = str(ex.get('sync_id') or '').strip()
        if ignore_sync_id and sid and sid == str(ignore_sync_id):
            continue
        if not endpoint_binds_listen(ep):
            continue
        l2 = str(ep.get('listen') or '').strip()
        h2, p2 = split_host_port(l2)
        if not p2 or int(p2) != cand_port:
            continue
        if not _hosts_overlap(cand_host, str(h2 or '').strip()):
            continue
        common = cand_proto & _proto_set(ep.get('protocol'))
        if not common:
            continue
        return {'type': 'endpoint', 'listen': l2, 'remark': str(ep.get('remark') or '').strip(), 'protocol': '/'.join(sorted(common)).upper()}
    if 'tcp' in cand_proto:
        tunnel_ports: Set[int] = set()
        for ep in eps:
            if not isinstance(ep, dict) or bool(ep.get('disabled', False)):
                continue
            ex = ep.get('extra_config')
            ex = ex if isinstance(ex, dict) else {}
            if str(ex.get('intranet_role') or '') != 'server':
                continue
            try:
                p = int(ex.get('intranet_server_port') or 0)
            except Exception:
                p = 0
            if p > 0:
                tunnel_ports.add(p)
        if cand_port in tunnel_ports:
            return {'type': 'intranet_tunnel', 'listen': f"0.0.0.0:{cand_port}", 'remark': '', 'protocol': 'TCP'}
    return None


def validate_remotes_list(remotes: Iterable[Any], *, where: str = '') -> List[str]:
    out: List[str] = []
    for x in remotes or []:
        s = str(x or '').strip()
        if not s:
            continue
        try:
            parse_addr(s)
        except PoolValidationError as exc:
            raise PoolValidationError(f"{where}{exc}")
        out.append(s)
    if not out:
        raise PoolValidationError(f"{where}目标地址不能为空")
    return out
