"""
Validators - 规则校验与规范化模块

提供规则保存前的完整校验：
- 端口冲突检测
- Remote 格式校验
- 权重行数匹配校验
- 高级参数校验
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Set


# ==================== 校验结果数据类 ====================

@dataclass
class ValidationError:
    """单个校验错误"""
    field: str           # 字段名
    message: str         # 错误消息
    rule_index: int = -1 # 规则索引 (-1 表示全局错误)
    severity: str = "error"  # error / warning


@dataclass
class ValidationResult:
    """校验结果"""
    valid: bool = True
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationError] = field(default_factory=list)
    normalized_pool: Optional[Dict[str, Any]] = None
    
    def add_error(self, field: str, message: str, rule_index: int = -1):
        self.valid = False
        self.errors.append(ValidationError(field, message, rule_index, "error"))
    
    def add_warning(self, field: str, message: str, rule_index: int = -1):
        self.warnings.append(ValidationError(field, message, rule_index, "warning"))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": [
                {"field": e.field, "message": e.message, "rule_index": e.rule_index}
                for e in self.errors
            ],
            "warnings": [
                {"field": w.field, "message": w.message, "rule_index": w.rule_index}
                for w in self.warnings
            ],
        }


# ==================== 端口解析工具 ====================

def parse_listen_port(listen: str) -> Optional[int]:
    """
    解析 listen 字符串中的端口号
    
    支持格式:
    - "8080"
    - ":8080"
    - "0.0.0.0:8080"
    - "[::]:8080"
    - "127.0.0.1:8080"
    """
    listen = str(listen or "").strip()
    if not listen:
        return None
    
    # 纯数字
    if listen.isdigit():
        return int(listen)
    
    # IPv6 格式 [::]:port
    if listen.startswith("["):
        match = re.match(r'\[([^\]]*)\]:(\d+)', listen)
        if match:
            return int(match.group(2))
    
    # 包含冒号的格式
    if ":" in listen:
        parts = listen.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            return int(parts[1])
    
    return None


def parse_remote_host_port(remote: str) -> Tuple[Optional[str], Optional[int]]:
    """
    解析 remote 字符串中的主机和端口
    
    支持格式:
    - "example.com:8080"
    - "192.168.1.1:8080"
    - "[2001:db8::1]:8080"
    """
    remote = str(remote or "").strip()
    if not remote:
        return None, None
    
    # IPv6 格式
    if remote.startswith("["):
        match = re.match(r'\[([^\]]+)\]:(\d+)', remote)
        if match:
            return match.group(1), int(match.group(2))
        return None, None
    
    # 普通格式
    if ":" in remote:
        parts = remote.rsplit(":", 1)
        if len(parts) == 2:
            host = parts[0]
            try:
                port = int(parts[1])
                return host, port
            except ValueError:
                pass
    
    return remote, None


# ==================== 格式校验函数 ====================

def validate_listen(listen: str) -> Tuple[bool, str]:
    """校验 listen 格式"""
    if not listen or not listen.strip():
        return False, "listen 不能为空"
    
    listen = listen.strip()
    port = parse_listen_port(listen)
    
    if port is None:
        return False, f"无法解析端口号: {listen}"
    
    if port < 1 or port > 65535:
        return False, f"端口号必须在 1-65535 之间: {port}"
    
    return True, ""


def validate_remote(remote: str) -> Tuple[bool, str]:
    """校验 remote 格式"""
    if not remote or not remote.strip():
        return False, "remote 不能为空"
    
    remote = remote.strip()
    
    # 检查 IPv6 格式
    if remote.startswith("["):
        match = re.match(r'\[([^\]]+)\]:(\d+)', remote)
        if not match:
            return False, f"IPv6 格式错误: {remote} (应为 [地址]:端口)"
        port = int(match.group(2))
        if port < 1 or port > 65535:
            return False, f"端口号必须在 1-65535 之间: {port}"
        return True, ""
    
    # 检查普通格式
    if ":" not in remote:
        return False, f"remote 格式错误: {remote} (应为 主机:端口)"
    
    host, port = parse_remote_host_port(remote)
    if host is None:
        return False, f"无法解析主机名: {remote}"
    if port is None:
        return False, f"无法解析端口号: {remote}"
    if port < 1 or port > 65535:
        return False, f"端口号必须在 1-65535 之间: {port}"
    
    # 检查主机名格式
    if not _is_valid_host(host):
        return False, f"主机名格式无效: {host}"
    
    return True, ""


def _is_valid_host(host: str) -> bool:
    """检查主机名是否有效"""
    if not host:
        return False
    
    # IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, host):
        parts = host.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    
    # 域名
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(domain_pattern, host))


def validate_weights(weights: List[Any], remote_count: int) -> Tuple[bool, str]:
    """校验权重列表"""
    if not weights:
        return True, ""  # 空权重是允许的
    
    if len(weights) != remote_count:
        return False, f"权重数量({len(weights)})与目标数量({remote_count})不匹配"
    
    for i, w in enumerate(weights):
        try:
            w_int = int(w)
            if w_int < 0:
                return False, f"权重值必须为非负整数: weights[{i}]={w}"
        except (ValueError, TypeError):
            return False, f"权重值必须为整数: weights[{i}]={w}"
    
    return True, ""


def validate_protocol(protocol: str) -> Tuple[bool, str]:
    """校验协议类型"""
    if not protocol:
        return True, ""  # 默认为 tcp+udp
    
    valid_protocols = {"tcp", "udp", "tcp+udp", "both"}
    if protocol.lower() not in valid_protocols:
        return False, f"无效的协议类型: {protocol} (允许: tcp, udp, tcp+udp)"
    
    return True, ""


def validate_balance(balance: str, remote_count: int) -> Tuple[bool, str]:
    """校验负载均衡配置"""
    if not balance:
        return True, ""
    
    balance = balance.strip().lower()
    
    # 简单算法名
    valid_algos = {"round_robin", "roundrobin", "iphash", "ip_hash", "random"}
    if balance in valid_algos:
        return True, ""
    
    # 带权重的格式: "roundrobin: 1, 2, 3"
    if ":" in balance:
        parts = balance.split(":", 1)
        algo = parts[0].strip().replace("_", "").replace("-", "")
        if algo not in {"roundrobin", "iphash", "random"}:
            return False, f"无效的负载均衡算法: {parts[0]}"
        
        if len(parts) > 1 and parts[1].strip():
            weights_str = parts[1].strip().split(",")
            if len(weights_str) != remote_count:
                return False, f"balance 中权重数量与目标数量不匹配"
    
    return True, ""


# ==================== 高级参数校验 ====================

def validate_extra_config(extra_config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """校验 extra_config 中的高级参数"""
    errors = []
    
    if not extra_config:
        return True, errors
    
    # WSS 参数校验
    if extra_config.get("listen_transport") == "ws":
        if not extra_config.get("listen_ws_host"):
            errors.append("WSS 监听模式需要设置 listen_ws_host")
    
    if extra_config.get("remote_transport") == "ws":
        if not extra_config.get("remote_ws_host"):
            errors.append("WSS 远程模式需要设置 remote_ws_host")
    
    # TLS 参数校验
    if extra_config.get("listen_tls_enabled"):
        # TLS 启用时可以有额外配置
        pass
    
    if extra_config.get("remote_tls_enabled"):
        # TLS 启用时可以有额外配置
        pass
    
    # 内网穿透参数校验
    if extra_config.get("intranet_role"):
        role = extra_config.get("intranet_role")
        if role not in ("server", "client"):
            errors.append(f"intranet_role 必须为 server 或 client: {role}")
        
        if role == "server" and not extra_config.get("intranet_server_port"):
            errors.append("内网穿透服务端需要设置 intranet_server_port")
    
    # PROXY Protocol 校验
    if extra_config.get("send_proxy_version"):
        version = extra_config.get("send_proxy_version")
        if version not in (1, 2, "1", "2"):
            errors.append(f"send_proxy_version 必须为 1 或 2: {version}")
    
    return len(errors) == 0, errors


# ==================== 规则端点校验 ====================

def validate_endpoint(endpoint: Dict[str, Any], index: int) -> ValidationResult:
    """校验单个规则端点"""
    result = ValidationResult()
    
    # 校验 listen
    listen = endpoint.get("listen", "")
    valid, msg = validate_listen(listen)
    if not valid:
        result.add_error("listen", msg, index)
    
    # 获取所有 remote
    remotes = []
    if endpoint.get("remote"):
        remotes.append(endpoint["remote"])
    if isinstance(endpoint.get("remotes"), list):
        remotes.extend(endpoint["remotes"])
    if isinstance(endpoint.get("extra_remotes"), list):
        remotes.extend(endpoint["extra_remotes"])
    
    # 暂停的规则可以没有 remote
    if not endpoint.get("disabled") and not remotes:
        result.add_error("remote", "至少需要一个目标地址", index)
    
    # 校验每个 remote
    for i, remote in enumerate(remotes):
        valid, msg = validate_remote(remote)
        if not valid:
            result.add_error(f"remotes[{i}]", msg, index)
    
    # 校验权重
    weights = endpoint.get("weights", [])
    if weights:
        valid, msg = validate_weights(weights, len(remotes))
        if not valid:
            result.add_error("weights", msg, index)
    
    # 校验协议
    protocol = endpoint.get("protocol", "")
    valid, msg = validate_protocol(protocol)
    if not valid:
        result.add_error("protocol", msg, index)
    
    # 校验负载均衡
    balance = endpoint.get("balance", "")
    valid, msg = validate_balance(balance, len(remotes))
    if not valid:
        result.add_error("balance", msg, index)
    
    # 校验高级参数
    extra_config = endpoint.get("extra_config", {})
    valid, errors = validate_extra_config(extra_config)
    for err in errors:
        result.add_error("extra_config", err, index)
    
    return result


# ==================== 端口冲突检测 ====================

def detect_port_conflicts(endpoints: List[Dict[str, Any]]) -> List[ValidationError]:
    """检测端口冲突"""
    conflicts = []
    port_map: Dict[int, List[int]] = {}  # port -> [rule_indices]
    
    for i, ep in enumerate(endpoints):
        if ep.get("disabled"):
            continue
        
        listen = ep.get("listen", "")
        port = parse_listen_port(listen)
        
        if port is not None:
            if port not in port_map:
                port_map[port] = []
            port_map[port].append(i)
    
    for port, indices in port_map.items():
        if len(indices) > 1:
            rule_nums = ", ".join(str(i + 1) for i in indices)
            conflicts.append(ValidationError(
                "listen",
                f"端口 {port} 被多个规则使用 (规则 #{rule_nums})",
                indices[0],
                "error"
            ))
    
    return conflicts


# ==================== 规则池完整校验 ====================

def validate_pool(pool: Dict[str, Any]) -> ValidationResult:
    """校验整个规则池"""
    result = ValidationResult()
    
    if not isinstance(pool, dict):
        result.add_error("pool", "规则池必须是对象类型")
        return result
    
    endpoints = pool.get("endpoints", [])
    if not isinstance(endpoints, list):
        result.add_error("endpoints", "endpoints 必须是数组类型")
        return result
    
    # 校验每个端点
    for i, ep in enumerate(endpoints):
        if not isinstance(ep, dict):
            result.add_error(f"endpoints[{i}]", "端点必须是对象类型", i)
            continue
        
        ep_result = validate_endpoint(ep, i)
        result.errors.extend(ep_result.errors)
        result.warnings.extend(ep_result.warnings)
        if not ep_result.valid:
            result.valid = False
    
    # 检测端口冲突
    conflicts = detect_port_conflicts(endpoints)
    for conflict in conflicts:
        result.errors.append(conflict)
        result.valid = False
    
    return result


# ==================== 规则规范化 ====================

def normalize_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """规范化单个规则端点"""
    normalized = {}
    
    # 基本字段
    normalized["listen"] = str(endpoint.get("listen", "")).strip()
    
    # 合并 remote/remotes
    remotes = []
    if endpoint.get("remote"):
        r = str(endpoint["remote"]).strip()
        if r:
            remotes.append(r)
    if isinstance(endpoint.get("remotes"), list):
        for r in endpoint["remotes"]:
            r = str(r).strip()
            if r and r not in remotes:
                remotes.append(r)
    
    if len(remotes) == 1:
        normalized["remote"] = remotes[0]
    elif len(remotes) > 1:
        normalized["remotes"] = remotes
    
    # extra_remotes
    if isinstance(endpoint.get("extra_remotes"), list):
        extra = [str(r).strip() for r in endpoint["extra_remotes"] if str(r).strip()]
        if extra:
            normalized["extra_remotes"] = extra
    
    # 权重
    if endpoint.get("weights"):
        weights = endpoint["weights"]
        if isinstance(weights, list):
            normalized["weights"] = [int(w) for w in weights]
    
    # 协议
    protocol = str(endpoint.get("protocol", "")).strip().lower()
    if protocol and protocol != "tcp+udp":
        normalized["protocol"] = protocol
    
    # 负载均衡
    balance = str(endpoint.get("balance", "")).strip()
    if balance:
        normalized["balance"] = balance
    
    # 暂停状态
    if endpoint.get("disabled"):
        normalized["disabled"] = True
    
    # 网络配置
    if isinstance(endpoint.get("network"), dict):
        normalized["network"] = endpoint["network"]
    
    # PROXY Protocol
    for key in ("accept_proxy", "accept_proxy_timeout", "send_proxy", "send_proxy_version"):
        if endpoint.get(key) is not None:
            normalized[key] = endpoint[key]
    
    # MPTCP
    for key in ("send_mptcp", "accept_mptcp"):
        if endpoint.get(key) is not None:
            normalized[key] = endpoint[key]
    
    # 接口
    for key in ("through", "interface", "listen_interface"):
        if endpoint.get(key):
            normalized[key] = str(endpoint[key]).strip()
    
    # 传输层
    for key in ("listen_transport", "remote_transport"):
        if endpoint.get(key):
            normalized[key] = str(endpoint[key]).strip()
    
    # 高级配置
    if isinstance(endpoint.get("extra_config"), dict):
        normalized["extra_config"] = endpoint["extra_config"]
    
    # 元数据 (备注、标签、收藏)
    for key in ("note", "tags", "favorite"):
        if endpoint.get(key) is not None:
            normalized[key] = endpoint[key]
    
    return normalized


def normalize_pool(pool: Dict[str, Any]) -> Dict[str, Any]:
    """规范化整个规则池"""
    normalized = {}
    
    # 网络配置
    if isinstance(pool.get("network"), dict):
        normalized["network"] = pool["network"]
    
    # 日志配置
    if isinstance(pool.get("log"), dict):
        normalized["log"] = pool["log"]
    
    # 端点
    endpoints = pool.get("endpoints", [])
    if isinstance(endpoints, list):
        normalized["endpoints"] = [
            normalize_endpoint(ep) 
            for ep in endpoints 
            if isinstance(ep, dict)
        ]
    else:
        normalized["endpoints"] = []
    
    return normalized


# ==================== 对外接口 ====================

def validate_and_normalize(pool: Dict[str, Any]) -> ValidationResult:
    """校验并规范化规则池"""
    result = validate_pool(pool)
    
    if result.valid:
        result.normalized_pool = normalize_pool(pool)
    
    return result


def quick_validate(pool: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """快速校验规则池，返回 (是否有效, 错误消息列表)"""
    result = validate_pool(pool)
    messages = [e.message for e in result.errors]
    return result.valid, messages
