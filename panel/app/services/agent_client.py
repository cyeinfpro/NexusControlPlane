"""
Unified Agent Client - 统一的 Agent 通信客户端

合并原有的 agent_client.py (同步) 和 agents.py (异步) 为单一模块，
提供一致的错误处理、重试机制和超时配置。
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse
import urllib.request

import httpx


# ==================== 配置常量 ====================

DEFAULT_TIMEOUT = 6.0
DEFAULT_AGENT_PORT = 18700
TCPING_TIMEOUT = 3.0
MAX_RETRIES = 2
RETRY_DELAY = 0.1


# ==================== 异常定义 ====================

class AgentError(Exception):
    """Agent 通信异常基类"""
    def __init__(self, message: str, status_code: int = 0, detail: str = ""):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.detail = detail


class AgentConnectionError(AgentError):
    """Agent 连接错误"""
    pass


class AgentTimeoutError(AgentError):
    """Agent 请求超时"""
    pass


class AgentResponseError(AgentError):
    """Agent 响应错误"""
    pass


# ==================== 错误处理工具 ====================

# 常见错误码翻译映射
ERROR_CODE_MAP = {
    'jq_failed': '生成配置失败（规则格式异常或 jq 不可用）',
    'restart_failed': '重启 realm 服务失败',
    'invalid api key': 'API Key 无效',
    'invalid_api_key': 'API Key 无效',
    'unauthorized': '未授权访问',
    'not_found': '资源不存在',
    'pool_invalid': '规则池配置无效',
    'apply_failed': '应用配置失败',
}


def _translate_error(error: str) -> str:
    """翻译错误码为友好提示"""
    key = str(error or "").strip().lower()
    return ERROR_CODE_MAP.get(key, str(error).strip())


def _format_agent_error(response: httpx.Response) -> str:
    """格式化 Agent 错误响应为友好提示"""
    data = _parse_json_response(response)
    error = None
    detail = None
    
    if isinstance(data, dict):
        error = data.get('error') or data.get('detail')
        detail = data.get('detail') if data.get('error') else None
    
    if not error:
        error = response.text.strip() or f"HTTP {response.status_code}"
    
    msg = _translate_error(error)
    
    if detail and str(detail).strip() and str(detail).strip() not in msg:
        d = str(detail).strip()
        if len(d) > 240:
            d = d[:240] + '…'
        msg = f"{msg}：{d}"
    
    return f"Agent 请求失败（{response.status_code}）：{msg}"


def _parse_json_response(response: httpx.Response) -> Dict[str, Any]:
    """安全解析 JSON 响应"""
    try:
        data = response.json()
    except Exception:
        return {"ok": False, "error": response.text}
    
    if isinstance(data, dict):
        return data
    return {"ok": False, "error": data}


def _should_retry_error(error: str) -> bool:
    """判断错误是否应该重试"""
    s = (error or "").lower()
    retry_keywords = (
        "timeout", "timed out", "temporar", 
        "connection aborted", "connection reset", 
        "broken pipe", "network unreachable"
    )
    return any(kw in s for kw in retry_keywords)


# ==================== 地址解析工具 ====================

def _extract_host_port(base_url: str, fallback_port: int = DEFAULT_AGENT_PORT) -> Tuple[str, int]:
    """从 base_url 提取主机和端口"""
    target = base_url.strip()
    if not target:
        return "", fallback_port
    if "://" not in target:
        target = f"http://{target}"
    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or fallback_port
    return host, port


def _normalize_base_url(base_url: str) -> str:
    """规范化 base_url"""
    url = str(base_url or "").strip().rstrip("/")
    if not url:
        return ""
    if "://" not in url:
        url = f"http://{url}"
    return url


# ==================== TCP Ping 工具 ====================

async def _tcp_ping_socket(host: str, port: int, timeout: float) -> float:
    """使用 socket 进行 TCP ping"""
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), 
            timeout=timeout
        )
    except asyncio.TimeoutError:
        raise AgentTimeoutError(f"TCP 连接超时 ({host}:{port})")
    except Exception as exc:
        raise AgentConnectionError(str(exc))
    
    try:
        latency = (time.monotonic() - start) * 1000
    finally:
        writer.close()
        await writer.wait_closed()
    
    return round(latency, 2)


async def _run_tcping_cmd(tcping: str, host: str, port: int) -> Tuple[str, int]:
    """运行 tcping 命令"""
    proc = await asyncio.create_subprocess_exec(
        tcping,
        "-c", "1",
        "-t", str(int(TCPING_TIMEOUT)),
        host, str(port),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), 
            timeout=TCPING_TIMEOUT + 1
        )
    except asyncio.TimeoutError:
        proc.kill()
        return "tcping timeout", 1
    
    output = (stdout or b"") + (stderr or b"")
    return output.decode(errors="ignore"), proc.returncode or 0


def _parse_tcping_latency(output: str) -> Optional[float]:
    """解析 tcping 输出中的延迟"""
    patterns = [
        r"time[=<]?\s*([0-9.]+)\s*ms",
        r"\bopen\b[^\n\r]*?([0-9.]+)\s*ms",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return float(match.group(1))
    return None


# ==================== 统一 Agent 客户端类 ====================

class AgentClient:
    """统一的 Agent 通信客户端"""
    
    def __init__(
        self, 
        base_url: str, 
        api_key: str, 
        verify_tls: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
    ):
        self.base_url = _normalize_base_url(base_url)
        self.api_key = api_key
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.max_retries = max_retries
    
    def _get_headers(self) -> Dict[str, str]:
        """获取请求头"""
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }
    
    def _build_url(self, path: str) -> str:
        """构建完整 URL"""
        return f"{self.base_url}{path}"
    
    # ==================== 异步方法 ====================
    
    async def get(
        self, 
        path: str, 
        timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        """异步 GET 请求"""
        url = self._build_url(path)
        headers = self._get_headers()
        
        async with httpx.AsyncClient(
            timeout=(timeout or self.timeout), 
            verify=self.verify_tls
        ) as client:
            for attempt in range(self.max_retries):
                try:
                    r = await client.get(url, headers=headers)
                    if r.status_code >= 400:
                        raise AgentResponseError(
                            _format_agent_error(r),
                            status_code=r.status_code
                        )
                    return _parse_json_response(r)
                except (httpx.TimeoutException, asyncio.TimeoutError) as e:
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(RETRY_DELAY)
                        continue
                    raise AgentTimeoutError(f"请求超时: {e}")
                except httpx.RequestError as e:
                    if attempt < self.max_retries - 1 and _should_retry_error(str(e)):
                        await asyncio.sleep(RETRY_DELAY)
                        continue
                    raise AgentConnectionError(f"连接失败: {e}")
    
    async def post(
        self, 
        path: str, 
        data: Any = None,
        timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        """异步 POST 请求"""
        url = self._build_url(path)
        headers = self._get_headers()
        
        async with httpx.AsyncClient(
            timeout=(timeout or self.timeout), 
            verify=self.verify_tls
        ) as client:
            for attempt in range(self.max_retries):
                try:
                    r = await client.post(url, headers=headers, json=data)
                    if r.status_code >= 400:
                        raise AgentResponseError(
                            _format_agent_error(r),
                            status_code=r.status_code
                        )
                    return _parse_json_response(r)
                except (httpx.TimeoutException, asyncio.TimeoutError) as e:
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(RETRY_DELAY)
                        continue
                    raise AgentTimeoutError(f"请求超时: {e}")
                except httpx.RequestError as e:
                    if attempt < self.max_retries - 1 and _should_retry_error(str(e)):
                        await asyncio.sleep(RETRY_DELAY)
                        continue
                    raise AgentConnectionError(f"连接失败: {e}")
    
    async def ping(self) -> Dict[str, Any]:
        """异步 TCP ping"""
        host, port = _extract_host_port(self.base_url, DEFAULT_AGENT_PORT)
        if not host:
            return {"ok": False, "error": "Agent 地址无效"}
        
        try:
            # 优先使用 tcping 命令
            tcping = shutil.which("tcping")
            if tcping:
                output, _code = await _run_tcping_cmd(tcping, host, port)
                latency = _parse_tcping_latency(output)
                if latency is not None:
                    return {"ok": True, "latency_ms": round(latency, 2)}
            
            # 回退到 socket ping
            latency_ms = await _tcp_ping_socket(host, port, TCPING_TIMEOUT)
            return {"ok": True, "latency_ms": latency_ms}
        
        except AgentError as e:
            return {"ok": False, "error": e.message}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    
    # ==================== 同步方法 ====================
    
    def get_sync(
        self, 
        path: str, 
        timeout: int = 6
    ) -> Any:
        """同步 GET 请求"""
        url = self._build_url(path)
        headers = self._get_headers()
        
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                if not raw:
                    return None
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            msg = e.read().decode("utf-8", errors="ignore")
            raise AgentResponseError(f"HTTP {e.code}: {msg}", status_code=e.code)
        except urllib.error.URLError as e:
            raise AgentConnectionError(str(e.reason))
        except Exception as e:
            raise AgentError(str(e))
    
    def post_sync(
        self, 
        path: str, 
        data: Any = None,
        timeout: int = 6
    ) -> Any:
        """同步 POST 请求"""
        url = self._build_url(path)
        headers = self._get_headers()
        body = json.dumps(data).encode("utf-8") if data is not None else None
        
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                if not raw:
                    return None
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            msg = e.read().decode("utf-8", errors="ignore")
            raise AgentResponseError(f"HTTP {e.code}: {msg}", status_code=e.code)
        except urllib.error.URLError as e:
            raise AgentConnectionError(str(e.reason))
        except Exception as e:
            raise AgentError(str(e))


# ==================== 便捷函数 (兼容旧代码) ====================

async def agent_get(
    base_url: str, 
    api_key: str, 
    path: str, 
    verify_tls: bool = False,
    timeout: Optional[float] = None
) -> Dict[str, Any]:
    """异步 GET 请求 (兼容旧接口)"""
    client = AgentClient(base_url, api_key, verify_tls, timeout or DEFAULT_TIMEOUT)
    return await client.get(path, timeout)


async def agent_post(
    base_url: str,
    api_key: str,
    path: str,
    data: Any = None,
    verify_tls: bool = False,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """异步 POST 请求 (兼容旧接口)"""
    client = AgentClient(base_url, api_key, verify_tls, timeout or DEFAULT_TIMEOUT)
    return await client.post(path, data, timeout)


async def agent_ping(
    base_url: str, 
    api_key: str, 
    verify_tls: bool = False
) -> Dict[str, Any]:
    """异步 TCP ping (兼容旧接口)"""
    client = AgentClient(base_url, api_key, verify_tls)
    return await client.ping()


def call_agent(
    base_url: str, 
    api_key: str, 
    path: str, 
    method: str = "GET", 
    body: Optional[Dict[str, Any]] = None
) -> Any:
    """同步请求 (兼容旧接口)"""
    client = AgentClient(base_url, api_key)
    if method.upper() == "POST":
        return client.post_sync(path, body)
    return client.get_sync(path)
