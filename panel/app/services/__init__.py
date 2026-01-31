"""
Services Package - 服务层模块

包含:
- agent_client: 统一的 Agent 通信客户端
- validators: 规则校验与规范化
"""

from .agent_client import (
    AgentClient,
    AgentError,
    AgentConnectionError,
    AgentTimeoutError,
    AgentResponseError,
    agent_get,
    agent_post,
    agent_ping,
    call_agent,
    DEFAULT_TIMEOUT,
    DEFAULT_AGENT_PORT,
)

from .validators import (
    ValidationResult,
    ValidationError,
    validate_pool,
    validate_endpoint,
    validate_and_normalize,
    quick_validate,
    normalize_pool,
    normalize_endpoint,
    parse_listen_port,
    parse_remote_host_port,
    detect_port_conflicts,
)

__all__ = [
    # Agent Client
    "AgentClient",
    "AgentError",
    "AgentConnectionError",
    "AgentTimeoutError",
    "AgentResponseError",
    "agent_get",
    "agent_post",
    "agent_ping",
    "call_agent",
    "DEFAULT_TIMEOUT",
    "DEFAULT_AGENT_PORT",
    # Validators
    "ValidationResult",
    "ValidationError",
    "validate_pool",
    "validate_endpoint",
    "validate_and_normalize",
    "quick_validate",
    "normalize_pool",
    "normalize_endpoint",
    "parse_listen_port",
    "parse_remote_host_port",
    "detect_port_conflicts",
]
