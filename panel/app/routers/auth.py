"""
Auth Router - 认证相关路由

包含:
- 登录/登出
- 初始设置
- 密码修改
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import load_credentials, save_credentials, verify_login

router = APIRouter(tags=["auth"])


# ==================== 工具函数 ====================

def _has_credentials() -> bool:
    """检查是否已设置凭据"""
    return bool(load_credentials())


def _set_flash(request: Request, msg: str):
    """设置闪存消息"""
    request.session["flash"] = msg


def _flash(request: Request) -> str:
    """获取并清除闪存消息"""
    msg = request.session.pop("flash", "")
    return msg


# ==================== 依赖函数 ====================

def require_login(request: Request) -> str:
    """API 登录验证依赖"""
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")
    return user


def require_login_page(request: Request) -> str:
    """页面登录验证依赖 (重定向到登录页)"""
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user


# ==================== 路由 ====================

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """登录页面"""
    from ..main import templates
    
    if not _has_credentials():
        return RedirectResponse(url="/setup", status_code=303)
    
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "user": None, "flash": _flash(request), "title": "登录"},
    )


@router.post("/login")
async def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """处理登录"""
    if not _has_credentials():
        _set_flash(request, "请先初始化面板账号")
        return RedirectResponse(url="/setup", status_code=303)
    
    if verify_login(username, password):
        request.session["user"] = username
        _set_flash(request, "登录成功")
        return RedirectResponse(url="/", status_code=303)
    
    _set_flash(request, "账号或密码错误")
    return RedirectResponse(url="/login", status_code=303)


@router.get("/logout")
async def logout(request: Request):
    """登出"""
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    """初始设置页面"""
    from ..main import templates
    
    if _has_credentials():
        return RedirectResponse(url="/login", status_code=303)
    
    return templates.TemplateResponse(
        "setup.html",
        {"request": request, "user": None, "flash": _flash(request), "title": "初始化账号"},
    )


@router.post("/setup")
async def setup_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
):
    """处理初始设置"""
    if _has_credentials():
        return RedirectResponse(url="/login", status_code=303)
    
    if password != confirm:
        _set_flash(request, "两次输入的密码不一致")
        return RedirectResponse(url="/setup", status_code=303)
    
    try:
        save_credentials(username, password)
    except ValueError as exc:
        _set_flash(request, str(exc))
        return RedirectResponse(url="/setup", status_code=303)
    
    _set_flash(request, "账号已初始化，请登录")
    return RedirectResponse(url="/login", status_code=303)


@router.post("/api/change-password")
async def api_change_password(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: str = Depends(require_login),
):
    """修改密码 API"""
    if new_password != confirm_password:
        return {"ok": False, "error": "两次输入的新密码不一致"}
    
    creds = load_credentials()
    if not creds:
        return {"ok": False, "error": "凭据不存在"}
    
    if not verify_login(creds.get("username", ""), old_password):
        return {"ok": False, "error": "旧密码错误"}
    
    try:
        save_credentials(creds.get("username", user), new_password)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    
    return {"ok": True}
