"""
Routers Package - 路由模块

包含:
- auth: 认证路由
- nodes: 节点管理路由
- stats: 统计监控路由
"""

from .auth import router as auth_router, require_login, require_login_page
from .nodes import router as nodes_router
from .stats import router as stats_router

__all__ = [
    "auth_router",
    "nodes_router",
    "stats_router",
    "require_login",
    "require_login_page",
]
