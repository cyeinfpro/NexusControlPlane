from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import re
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Tuple

from fastapi import FastAPI

from ..clients.agent import agent_get_raw, agent_post
from ..core.bg_tasks import spawn_background_task
from ..db import get_node, get_panel_setting, list_nodes, set_panel_setting
from .panel_config import parse_bool_loose

logger = logging.getLogger(__name__)

_AUTO_BACKUP_BG_ENABLED = (os.getenv("REALM_AUTO_BACKUP_BG_ENABLED") or "1").strip().lower() not in (
    "0",
    "false",
    "off",
    "no",
)

_AUTO_BACKUP_LOOP_INTERVAL_SEC = 20.0
try:
    _AUTO_BACKUP_LOOP_INTERVAL_SEC = float((os.getenv("REALM_AUTO_BACKUP_LOOP_INTERVAL_SEC") or "20").strip() or 20)
except Exception:
    _AUTO_BACKUP_LOOP_INTERVAL_SEC = 20.0
if _AUTO_BACKUP_LOOP_INTERVAL_SEC < 5.0:
    _AUTO_BACKUP_LOOP_INTERVAL_SEC = 5.0
if _AUTO_BACKUP_LOOP_INTERVAL_SEC > 300.0:
    _AUTO_BACKUP_LOOP_INTERVAL_SEC = 300.0

_AUTO_BACKUP_UPLOAD_CHUNK_SIZE = 512 * 1024
try:
    _AUTO_BACKUP_UPLOAD_CHUNK_SIZE = int(
        float((os.getenv("REALM_AUTO_BACKUP_UPLOAD_CHUNK_SIZE") or str(_AUTO_BACKUP_UPLOAD_CHUNK_SIZE)).strip())
    )
except Exception:
    _AUTO_BACKUP_UPLOAD_CHUNK_SIZE = 512 * 1024
if _AUTO_BACKUP_UPLOAD_CHUNK_SIZE < 64 * 1024:
    _AUTO_BACKUP_UPLOAD_CHUNK_SIZE = 64 * 1024
if _AUTO_BACKUP_UPLOAD_CHUNK_SIZE > 2 * 1024 * 1024:
    _AUTO_BACKUP_UPLOAD_CHUNK_SIZE = 2 * 1024 * 1024

_AUTO_BACKUP_FILE_RE = re.compile(r"^nexus-auto-backup-(\d{8})-(\d{6})\.zip$")
_WIN_ABS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/].*")

_SET_ENABLED = "auto_backup_enabled"
_SET_TARGET_NODE_ID = "auto_backup_target_node_id"
_SET_TARGET_PATH = "auto_backup_target_path"
_SET_INTERVAL_HOURS = "auto_backup_interval_hours"
_SET_RETENTION_DAYS = "auto_backup_retention_days"
_SET_KEEP_COUNT = "auto_backup_keep_count"

_SET_LAST_TRIGGER_TS = "auto_backup_last_trigger_ts"
_SET_LAST_SUCCESS_TS = "auto_backup_last_success_ts"
_SET_LAST_STATUS = "auto_backup_last_status"
_SET_LAST_MESSAGE = "auto_backup_last_message"
_SET_LAST_FILENAME = "auto_backup_last_filename"
_SET_LAST_SIZE_BYTES = "auto_backup_last_size_bytes"


def enabled() -> bool:
    return bool(_AUTO_BACKUP_BG_ENABLED)


def _safe_int(raw: Any, default: int = 0) -> int:
    try:
        return int(raw)
    except Exception:
        try:
            return int(float(str(raw).strip()))
        except Exception:
            return int(default)


def _safe_float(raw: Any, default: float = 0.0) -> float:
    try:
        return float(raw)
    except Exception:
        try:
            return float(str(raw).strip())
        except Exception:
            return float(default)


def _clamp_int(raw: Any, default: int, lo: int, hi: int) -> int:
    v = _safe_int(raw, default)
    if v < int(lo):
        v = int(lo)
    if v > int(hi):
        v = int(hi)
    return int(v)


def _clean_path(raw: Any, max_len: int = 255) -> str:
    s = str(raw or "").replace("\r", "").replace("\n", "").strip()
    if len(s) > int(max_len):
        s = s[: int(max_len)].strip()
    return s


def _is_absolute_path(path: str) -> bool:
    p = str(path or "").strip()
    if not p:
        return False
    if p.startswith("/"):
        return True
    if _WIN_ABS_PATH_RE.match(p):
        return True
    return False


def _set_setting_safe(key: str, value: Any) -> None:
    try:
        set_panel_setting(str(key or "").strip(), str(value if value is not None else ""))
    except Exception:
        logger.exception("auto backup set_panel_setting failed key=%s", str(key or ""))


def _auto_backup_filename(ts: float = 0.0) -> str:
    try:
        ts_f = float(ts)
    except Exception:
        ts_f = 0.0
    base_ts = ts_f if ts_f > 0.0 else time.time()
    try:
        dt = datetime.fromtimestamp(base_ts)
    except Exception:
        dt = datetime.now()
    return f"nexus-auto-backup-{dt.strftime('%Y%m%d-%H%M%S')}.zip"


def _backup_agent_target(node: Dict[str, Any]) -> Tuple[str, bool]:
    from ..routers.api_nodes import _backup_agent_request_target

    return _backup_agent_request_target(node)


async def _build_backup_bundle() -> Dict[str, Any]:
    from ..routers.api_nodes import _build_full_backup_bundle

    return await _build_full_backup_bundle(
        request=None,
        progress_callback=None,
        nodes_override=list_nodes(),
        include_content=False,
        panel_public_url_override="",
    )


async def _upload_backup_file(node: Dict[str, Any], root_path: str, local_file: str, filename: str) -> int:
    target_base_url, target_verify_tls = _backup_agent_target(node)
    if not target_base_url:
        raise RuntimeError("目标节点地址为空")
    if not os.path.exists(local_file):
        raise RuntimeError("备份文件不存在")

    file_size = int(max(0, os.path.getsize(local_file)))
    root_clean = str(root_path or "").strip()
    if not root_clean:
        raise RuntimeError("目标路径为空")
    filename_clean = os.path.basename(str(filename or "").strip()) or _auto_backup_filename()
    if not _AUTO_BACKUP_FILE_RE.match(filename_clean):
        raise RuntimeError("自动备份文件名非法")

    upload_id = uuid.uuid4().hex
    api_key = str(node.get("api_key") or "")
    node_name = str(node.get("name") or f"#{_safe_int(node.get('id'), 0)}")

    if file_size <= 0:
        payload_empty = {
            "root": root_clean,
            "path": "",
            "filename": filename_clean,
            "upload_id": upload_id,
            "offset": 0,
            "done": True,
            "allow_empty": True,
            "root_base": root_clean,
        }
        resp_empty = await agent_post(
            target_base_url,
            api_key,
            "/api/v1/website/files/upload_chunk",
            payload_empty,
            target_verify_tls,
            timeout=30.0,
        )
        if not bool(resp_empty.get("ok", False)):
            raise RuntimeError(str(resp_empty.get("error") or "空文件上传失败"))
        logger.info("auto backup uploaded empty file node=%s file=%s", node_name, filename_clean)
        return 0

    uploaded = 0
    with open(local_file, "rb") as rf:
        while True:
            chunk = rf.read(int(_AUTO_BACKUP_UPLOAD_CHUNK_SIZE))
            if not chunk:
                break
            done = (uploaded + len(chunk)) >= file_size
            payload = {
                "root": root_clean,
                "path": "",
                "filename": filename_clean,
                "upload_id": upload_id,
                "offset": uploaded,
                "done": done,
                "content_b64": base64.b64encode(chunk).decode("ascii"),
                "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
                "root_base": root_clean,
            }
            resp = await agent_post(
                target_base_url,
                api_key,
                "/api/v1/website/files/upload_chunk",
                payload,
                target_verify_tls,
                timeout=90.0,
            )
            if not bool(resp.get("ok", False)):
                err = str(resp.get("error") or "分片上传失败").strip()
                expected = _safe_int(resp.get("expected_offset"), -1)
                if expected >= 0:
                    err = f"{err}（expected_offset={expected}）"
                raise RuntimeError(err)
            uploaded += len(chunk)

    logger.info("auto backup uploaded node=%s file=%s bytes=%d", node_name, filename_clean, int(uploaded))
    return int(uploaded)


def _file_ts_from_name_or_mtime(name: str, mtime_text: str = "") -> float:
    fname = str(name or "").strip()
    m = _AUTO_BACKUP_FILE_RE.match(fname)
    if m:
        try:
            dt = datetime.strptime(f"{m.group(1)}{m.group(2)}", "%Y%m%d%H%M%S")
            return float(dt.timestamp())
        except Exception:
            pass
    mt = str(mtime_text or "").strip()
    if mt:
        try:
            return float(datetime.strptime(mt, "%Y-%m-%d %H:%M:%S").timestamp())
        except Exception:
            pass
    return 0.0


async def _list_remote_backup_files(
    node: Dict[str, Any],
    root_path: str,
) -> Tuple[str, bool, List[Dict[str, Any]]]:
    target_base_url, target_verify_tls = _backup_agent_target(node)
    if not target_base_url:
        raise RuntimeError("目标节点地址为空")
    api_key = str(node.get("api_key") or "")
    root_clean = str(root_path or "").strip()

    resp = await agent_get_raw(
        target_base_url,
        api_key,
        "/api/v1/website/files/list",
        target_verify_tls,
        params={
            "root": root_clean,
            "path": "",
            "root_base": root_clean,
        },
        timeout=30.0,
    )
    try:
        data = resp.json()
    except Exception:
        text = ""
        try:
            text = str(resp.text or "").strip()
        except Exception:
            text = ""
        raise RuntimeError(text or f"读取远端目录失败（HTTP {int(resp.status_code)}）")

    if int(resp.status_code) < 200 or int(resp.status_code) >= 300:
        err = str((data or {}).get("error") or "").strip() if isinstance(data, dict) else ""
        raise RuntimeError(err or f"读取远端目录失败（HTTP {int(resp.status_code)}）")
    if not isinstance(data, dict) or not bool(data.get("ok")):
        err = str((data or {}).get("error") or "").strip() if isinstance(data, dict) else ""
        raise RuntimeError(err or "读取远端目录失败")

    items_raw = data.get("items")
    items = items_raw if isinstance(items_raw, list) else []
    files: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if bool(item.get("is_dir")):
            continue
        name = str(item.get("name") or "").strip()
        if not _AUTO_BACKUP_FILE_RE.match(name):
            continue
        rel_path = str(item.get("path") or "").strip()
        if not rel_path:
            rel_path = name
        # Strictly manage only root-level auto-backup files to avoid touching unrelated files.
        if rel_path != name:
            continue
        files.append(
            {
                "name": name,
                "path": rel_path,
                "ts": _file_ts_from_name_or_mtime(name, str(item.get("mtime") or "")),
            }
        )
    files.sort(key=lambda row: (float(row.get("ts") or 0.0), str(row.get("name") or "")), reverse=True)
    return target_base_url, bool(target_verify_tls), files


async def _delete_remote_file(
    node: Dict[str, Any],
    target_base_url: str,
    target_verify_tls: bool,
    root_path: str,
    rel_path: str,
) -> bool:
    api_key = str(node.get("api_key") or "")
    payload = {
        "root": str(root_path or "").strip(),
        "path": str(rel_path or "").strip(),
        "root_base": str(root_path or "").strip(),
    }
    resp = await agent_post(
        target_base_url,
        api_key,
        "/api/v1/website/files/delete",
        payload,
        target_verify_tls,
        timeout=30.0,
    )
    if bool(resp.get("ok")):
        return True
    err = str(resp.get("error") or "").strip()
    logger.warning("auto backup delete remote file failed path=%s err=%s", str(rel_path or ""), err or "unknown")
    return False


async def _cleanup_remote_backups(node: Dict[str, Any], root_path: str, retention_days: int, keep_count: int) -> Dict[str, int]:
    target_base_url, target_verify_tls, files = await _list_remote_backup_files(node, root_path)
    deleted_age = 0
    deleted_count = 0
    deleted_paths: set[str] = set()

    if retention_days > 0:
        cutoff = time.time() - (int(retention_days) * 24 * 3600)
        for row in files:
            ts = _safe_float(row.get("ts"), 0.0)
            rel_path = str(row.get("path") or "").strip()
            if not rel_path or ts <= 0.0:
                continue
            if ts >= cutoff:
                continue
            ok = await _delete_remote_file(node, target_base_url, target_verify_tls, root_path, rel_path)
            if ok:
                deleted_age += 1
                deleted_paths.add(rel_path)

    survivors = [row for row in files if str(row.get("path") or "").strip() not in deleted_paths]
    if keep_count > 0 and len(survivors) > int(keep_count):
        for row in survivors[int(keep_count) :]:
            rel_path = str(row.get("path") or "").strip()
            if not rel_path:
                continue
            ok = await _delete_remote_file(node, target_base_url, target_verify_tls, root_path, rel_path)
            if ok:
                deleted_count += 1
                deleted_paths.add(rel_path)

    return {
        "deleted_age": int(deleted_age),
        "deleted_count": int(deleted_count),
        "total": int(len(files)),
    }


def _load_auto_backup_cfg() -> Dict[str, Any]:
    enabled_cfg = parse_bool_loose(get_panel_setting(_SET_ENABLED), default=False)
    target_node_id = _clamp_int(get_panel_setting(_SET_TARGET_NODE_ID), default=0, lo=0, hi=2147483647)
    target_path = _clean_path(get_panel_setting(_SET_TARGET_PATH), max_len=255)
    if target_path and not _is_absolute_path(target_path):
        target_path = ""
    interval_hours = _clamp_int(get_panel_setting(_SET_INTERVAL_HOURS), default=24, lo=1, hi=24 * 30)
    retention_days = _clamp_int(get_panel_setting(_SET_RETENTION_DAYS), default=30, lo=0, hi=3650)
    keep_count = _clamp_int(get_panel_setting(_SET_KEEP_COUNT), default=30, lo=0, hi=2000)
    last_trigger_ts = _safe_float(get_panel_setting(_SET_LAST_TRIGGER_TS), 0.0)
    return {
        "enabled": bool(enabled_cfg),
        "target_node_id": int(target_node_id),
        "target_path": target_path,
        "interval_hours": int(interval_hours),
        "retention_days": int(retention_days),
        "keep_count": int(keep_count),
        "last_trigger_ts": float(last_trigger_ts),
    }


async def _run_auto_backup_once(cfg: Dict[str, Any]) -> Dict[str, Any]:
    target_node_id = _safe_int(cfg.get("target_node_id"), 0)
    target_path = str(cfg.get("target_path") or "").strip()
    if target_node_id <= 0:
        raise RuntimeError("未配置自动备份目标节点")
    if not target_path:
        raise RuntimeError("未配置自动备份目标路径")

    node = get_node(target_node_id)
    if not isinstance(node, dict):
        raise RuntimeError("自动备份目标节点不存在")

    bundle_path = ""
    filename = ""
    size_bytes = 0
    try:
        bundle = await _build_backup_bundle()
        bundle_path = str(bundle.get("zip_path") or "").strip()
        filename = _auto_backup_filename()
        if not bundle_path:
            raise RuntimeError("备份包路径为空")
        if not os.path.exists(bundle_path):
            raise RuntimeError("备份包生成失败")

        size_bytes = int(max(0, os.path.getsize(bundle_path)))
        uploaded = await _upload_backup_file(node, target_path, bundle_path, filename)
        cleanup: Dict[str, Any] = {"deleted_age": 0, "deleted_count": 0, "total": 0}
        cleanup_error = ""
        try:
            cleanup = await _cleanup_remote_backups(
                node,
                target_path,
                _safe_int(cfg.get("retention_days"), 0),
                _safe_int(cfg.get("keep_count"), 0),
            )
        except Exception as exc:
            cleanup_error = str(exc or "").strip()
            logger.warning("auto backup cleanup failed node_id=%d path=%s err=%s", target_node_id, target_path, cleanup_error)
        return {
            "filename": filename,
            "size_bytes": int(size_bytes),
            "uploaded_bytes": int(uploaded),
            "cleanup": cleanup,
            "cleanup_error": cleanup_error,
        }
    finally:
        if bundle_path:
            try:
                os.remove(bundle_path)
            except Exception:
                pass


async def _auto_backup_loop() -> None:
    while True:
        try:
            cfg = _load_auto_backup_cfg()
            if not bool(cfg.get("enabled")):
                await asyncio.sleep(float(_AUTO_BACKUP_LOOP_INTERVAL_SEC))
                continue

            target_node_id = _safe_int(cfg.get("target_node_id"), 0)
            target_path = str(cfg.get("target_path") or "").strip()
            interval_sec = max(3600.0, float(_safe_int(cfg.get("interval_hours"), 24)) * 3600.0)
            last_trigger_ts = _safe_float(cfg.get("last_trigger_ts"), 0.0)
            now_ts = time.time()

            if target_node_id <= 0 or not target_path:
                await asyncio.sleep(float(_AUTO_BACKUP_LOOP_INTERVAL_SEC))
                continue

            if last_trigger_ts > 0.0 and (now_ts - last_trigger_ts) < interval_sec:
                await asyncio.sleep(float(_AUTO_BACKUP_LOOP_INTERVAL_SEC))
                continue

            _set_setting_safe(_SET_LAST_TRIGGER_TS, str(int(now_ts)))

            try:
                result = await _run_auto_backup_once(cfg)
                ok_ts = int(time.time())
                cleanup = result.get("cleanup") if isinstance(result.get("cleanup"), dict) else {}
                deleted_age = _safe_int((cleanup or {}).get("deleted_age"), 0)
                deleted_count = _safe_int((cleanup or {}).get("deleted_count"), 0)
                msg = (
                    f"上传成功：{_safe_int(result.get('uploaded_bytes'), 0)} bytes，"
                    f"清理过期 {deleted_age} 个，清理超量 {deleted_count} 个"
                )
                cleanup_error = str(result.get("cleanup_error") or "").strip()
                if cleanup_error:
                    msg = f"{msg}（清理异常：{cleanup_error}）"
                _set_setting_safe(_SET_LAST_SUCCESS_TS, str(ok_ts))
                _set_setting_safe(_SET_LAST_STATUS, "success")
                _set_setting_safe(_SET_LAST_MESSAGE, msg[:300])
                _set_setting_safe(_SET_LAST_FILENAME, str(result.get("filename") or "")[:200])
                _set_setting_safe(_SET_LAST_SIZE_BYTES, str(_safe_int(result.get("size_bytes"), 0)))
                logger.info(
                    "auto backup success node_id=%d path=%s file=%s bytes=%d",
                    target_node_id,
                    target_path,
                    str(result.get("filename") or ""),
                    _safe_int(result.get("size_bytes"), 0),
                )
            except Exception as exc:
                err_msg = str(exc or "未知错误").strip() or "未知错误"
                _set_setting_safe(_SET_LAST_STATUS, "failed")
                _set_setting_safe(_SET_LAST_MESSAGE, err_msg[:300])
                logger.exception("auto backup failed node_id=%d path=%s", target_node_id, target_path)
        except Exception:
            logger.exception("auto backup loop crashed")
        await asyncio.sleep(float(_AUTO_BACKUP_LOOP_INTERVAL_SEC))


async def start_background(app: FastAPI) -> None:
    if not enabled():
        return
    task = getattr(app.state, "auto_backup_task", None)
    if isinstance(task, asyncio.Task) and not task.done():
        return
    try:
        task = spawn_background_task(_auto_backup_loop(), label="auto-backup")
    except Exception:
        return
    app.state.auto_backup_task = task
    app.state.auto_backup_started = True
