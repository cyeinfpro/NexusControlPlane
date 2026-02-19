from __future__ import annotations

import calendar
import base64
import gzip
import io
import json
import logging
import os
import re
import shlex
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:
    Fernet = None
    InvalidToken = Exception

from ..core.deps import require_login
from ..core.paths import STATIC_DIR
from ..db import (
    add_certificate,
    add_site_event,
    delete_certificates_by_site,
    delete_certificates_by_node,
    delete_site,
    delete_site_checks,
    delete_site_events,
    get_task,
    get_site,
    get_desired_pool,
    get_group_orders,
    get_node_runtime,
    get_panel_setting,
    insert_netmon_samples,
    list_certificates,
    list_sites,
    list_tasks,
    list_nodes,
    node_auto_restart_policy_from_row,
    set_agent_rollout_all,
    set_desired_pool,
    set_desired_pool_exact,
    set_desired_pool_version_exact,
    set_panel_setting,
    update_certificate,
    update_node_basic,
    update_agent_status,
    update_netmon_monitor,
    update_node_report,
    update_site,
    update_site_health,
    update_task,
)
from ..services.agent_commands import sign_cmd, single_rule_ops
from ..services.adaptive_lb import suggest_adaptive_pool_patch
from ..services.assets import (
    agent_asset_urls,
    agent_fallback_asset_urls,
    file_sha256,
    panel_public_base_url,
    parse_agent_version_from_ua,
    read_latest_agent_version,
)
try:
    from ..services.panel_config import setting_bool, setting_int, setting_str
except Exception:
    def _cfg_env(names: Optional[list[str]]) -> str:
        for n in (names or []):
            name = str(n or "").strip()
            if not name:
                continue
            v = str(os.getenv(name) or "").strip()
            if v:
                return v
        return ""

    def setting_bool(
        key: str,
        default: bool = False,
        env_names: Optional[list[str]] = None,
    ) -> bool:
        raw = _cfg_env(env_names)
        s = str(raw).strip().lower()
        if not s:
            return bool(default)
        if s in ("1", "true", "yes", "on", "y"):
            return True
        if s in ("0", "false", "no", "off", "n"):
            return False
        return bool(default)

    def setting_int(
        key: str,
        default: int,
        lo: int,
        hi: int,
        env_names: Optional[list[str]] = None,
    ) -> int:
        raw = _cfg_env(env_names)
        try:
            v = int(float(raw if raw else default))
        except Exception:
            v = int(default)
        if v < int(lo):
            v = int(lo)
        if v > int(hi):
            v = int(hi)
        return int(v)

    def setting_str(
        key: str,
        default: str = "",
        env_names: Optional[list[str]] = None,
    ) -> str:
        raw = _cfg_env(env_names)
        s = str(raw).strip()
        if s:
            return s
        return str(default or "")
from ..services.node_status import is_report_fresh
from ..services.stats_history import ingest_stats_snapshot

router = APIRouter()
logger = logging.getLogger(__name__)

_PANEL_UPDATE_STATE_KEY = "panel_self_update_state_json"
_PANEL_UPDATE_LOCK = threading.Lock()
_PANEL_UPDATE_JOBS: Dict[str, Dict[str, Any]] = {}
_PANEL_UPDATE_WORKER: Optional[threading.Thread] = None
_PANEL_UPDATE_WORKER_JOB_ID = ""
_PANEL_UPDATE_LOG_MAX = 240
_PANEL_UPDATE_STALE_SEC = 1800.0
_PANEL_UPDATE_LINE_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_PANEL_UPDATE_ACTIVE_STATES = {"running", "restarting"}
_PANEL_UPDATE_TERMINAL_STATES = {"done", "failed"}


def _panel_update_now_text(ts: Optional[float] = None) -> str:
    base = float(ts if ts is not None else time.time())
    try:
        return datetime.fromtimestamp(base).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _panel_update_parse_ts(raw: Any) -> float:
    text = str(raw or "").strip()
    if not text:
        return 0.0
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").timestamp()
    except Exception:
        return 0.0


def _panel_update_canon_status(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    if s in _PANEL_UPDATE_ACTIVE_STATES or s in _PANEL_UPDATE_TERMINAL_STATES:
        return s
    if s in ("ok", "success", "completed"):
        return "done"
    if s in ("error", "timeout", "stale"):
        return "failed"
    return "running"


def _panel_update_sanitize_line(raw: Any) -> str:
    text = str(raw or "")
    if not text:
        return ""
    text = text.replace("\x00", "")
    text = _PANEL_UPDATE_LINE_ANSI_RE.sub("", text)
    text = text.replace("\r", "\n")
    lines = [str(x or "").strip() for x in text.splitlines() if str(x or "").strip()]
    if not lines:
        return ""
    line = str(lines[-1] or "").strip()
    if len(line) > 420:
        line = line[:420].rstrip() + "..."
    return line


def _panel_update_progress_hint(line: str, current_progress: int, current_stage: str) -> Tuple[int, str, str, str]:
    text = str(line or "").strip()
    p = max(0, min(100, int(current_progress or 0)))
    stage = str(current_stage or "").strip() or "更新中"
    hint_status = ""
    hint_msg = ""
    if not text:
        return p, stage, hint_status, hint_msg

    m = re.search(r"文件拉取进度.*\((\d+)\s*/\s*(\d+)\)", text)
    if m:
        done = max(0, int(m.group(1) or 0))
        total = max(1, int(m.group(2) or 1))
        pct = max(0.0, min(1.0, float(done) / float(total)))
        p = max(p, int(18 + pct * 30))
        stage = f"拉取更新文件 {done}/{total}"

    hints: List[Tuple[str, int, str]] = [
        ("依赖已满足", 8, "依赖检查完成"),
        ("安装缺失依赖", 8, "安装更新依赖"),
        ("拉取仓库文件清单", 14, "读取更新清单"),
        ("优先使用文件清单拉取", 14, "读取更新清单"),
        ("开始拉取文件", 20, "拉取更新文件"),
        ("仓库文件拉取完成", 50, "更新文件已下载"),
        ("解压中", 54, "解压更新包"),
        ("已定位 panel 目录", 58, "校验更新结构"),
        ("更新面板程序文件", 64, "覆盖面板程序"),
        ("打包 Agent 离线安装包", 72, "更新 Agent 安装包"),
        ("同步 realm 二进制", 78, "同步二进制资源"),
        ("安装/更新 Python 依赖", 84, "更新运行依赖"),
        ("Python 依赖未变化", 84, "依赖检查完成"),
        ("虚拟环境不存在，重新创建", 84, "重建运行环境"),
        ("systemctl daemon-reload", 92, "刷新服务配置"),
        ("systemctl restart realm-panel.service", 96, "重启面板服务"),
        ("面板已更新并重启", 100, "更新完成"),
    ]
    for marker, marker_p, marker_stage in hints:
        if marker in text:
            p = max(p, int(marker_p))
            stage = marker_stage

    lower = text.lower()
    if ("restart realm-panel.service" in lower) or ("systemctl restart realm-panel.service" in lower):
        p = max(p, 96)
        stage = "重启面板服务"
        hint_status = "restarting"
    if "面板已更新并重启" in text:
        p = 100
        stage = "更新完成"
        hint_status = "done"

    if text.startswith("[错误]") or "请使用 root 运行" in text:
        hint_msg = text

    return max(0, min(100, int(p))), stage, hint_status, hint_msg


def _panel_update_persist(snapshot: Dict[str, Any]) -> None:
    if not isinstance(snapshot, dict):
        return
    payload = {
        "job_id": str(snapshot.get("job_id") or "").strip(),
        "status": _panel_update_canon_status(snapshot.get("status")),
        "progress": max(0, min(100, int(snapshot.get("progress") or 0))),
        "stage": str(snapshot.get("stage") or "").strip(),
        "message": str(snapshot.get("message") or "").strip(),
        "source": str(snapshot.get("source") or "").strip(),
        "started_at": str(snapshot.get("started_at") or "").strip(),
        "updated_at": str(snapshot.get("updated_at") or "").strip(),
        "finished_at": str(snapshot.get("finished_at") or "").strip(),
    }
    try:
        set_panel_setting(_PANEL_UPDATE_STATE_KEY, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        pass


def _panel_update_load_persisted(job_id: str = "") -> Optional[Dict[str, Any]]:
    raw = str(get_panel_setting(_PANEL_UPDATE_STATE_KEY, "") or "").strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    jid = str(data.get("job_id") or "").strip()
    if not jid:
        return None
    want = str(job_id or "").strip()
    if want and want != jid:
        return None
    return {
        "job_id": jid,
        "status": _panel_update_canon_status(data.get("status")),
        "progress": max(0, min(100, int(data.get("progress") or 0))),
        "stage": str(data.get("stage") or "").strip(),
        "message": str(data.get("message") or "").strip(),
        "source": str(data.get("source") or "").strip(),
        "started_at": str(data.get("started_at") or "").strip(),
        "updated_at": str(data.get("updated_at") or "").strip(),
        "finished_at": str(data.get("finished_at") or "").strip(),
        "logs": [],
    }


def _panel_update_snapshot(job_id: str = "") -> Optional[Dict[str, Any]]:
    want = str(job_id or "").strip()
    with _PANEL_UPDATE_LOCK:
        if want and isinstance(_PANEL_UPDATE_JOBS.get(want), dict):
            src = _PANEL_UPDATE_JOBS.get(want) or {}
            return {
                "job_id": str(src.get("job_id") or want),
                "status": _panel_update_canon_status(src.get("status")),
                "progress": max(0, min(100, int(src.get("progress") or 0))),
                "stage": str(src.get("stage") or "").strip(),
                "message": str(src.get("message") or "").strip(),
                "source": str(src.get("source") or "").strip(),
                "started_at": str(src.get("started_at") or "").strip(),
                "updated_at": str(src.get("updated_at") or "").strip(),
                "finished_at": str(src.get("finished_at") or "").strip(),
                "logs": list(src.get("logs") or []),
            }
        if (not want) and _PANEL_UPDATE_WORKER_JOB_ID and isinstance(_PANEL_UPDATE_JOBS.get(_PANEL_UPDATE_WORKER_JOB_ID), dict):
            src = _PANEL_UPDATE_JOBS.get(_PANEL_UPDATE_WORKER_JOB_ID) or {}
            return {
                "job_id": str(src.get("job_id") or _PANEL_UPDATE_WORKER_JOB_ID),
                "status": _panel_update_canon_status(src.get("status")),
                "progress": max(0, min(100, int(src.get("progress") or 0))),
                "stage": str(src.get("stage") or "").strip(),
                "message": str(src.get("message") or "").strip(),
                "source": str(src.get("source") or "").strip(),
                "started_at": str(src.get("started_at") or "").strip(),
                "updated_at": str(src.get("updated_at") or "").strip(),
                "finished_at": str(src.get("finished_at") or "").strip(),
                "logs": list(src.get("logs") or []),
            }
        if (not want) and _PANEL_UPDATE_JOBS:
            latest = sorted(
                _PANEL_UPDATE_JOBS.values(),
                key=lambda x: _panel_update_parse_ts((x or {}).get("updated_at")),
                reverse=True,
            )[0]
            src = latest if isinstance(latest, dict) else {}
            return {
                "job_id": str(src.get("job_id") or ""),
                "status": _panel_update_canon_status(src.get("status")),
                "progress": max(0, min(100, int(src.get("progress") or 0))),
                "stage": str(src.get("stage") or "").strip(),
                "message": str(src.get("message") or "").strip(),
                "source": str(src.get("source") or "").strip(),
                "started_at": str(src.get("started_at") or "").strip(),
                "updated_at": str(src.get("updated_at") or "").strip(),
                "finished_at": str(src.get("finished_at") or "").strip(),
                "logs": list(src.get("logs") or []),
            }
    return _panel_update_load_persisted(want)


def _panel_update_worker_alive(job_id: str = "") -> bool:
    want = str(job_id or "").strip()
    with _PANEL_UPDATE_LOCK:
        t = _PANEL_UPDATE_WORKER
        jid = str(_PANEL_UPDATE_WORKER_JOB_ID or "").strip()
    alive = bool(t is not None and t.is_alive())
    if not alive:
        return False
    if want and jid != want:
        return False
    return True


def _panel_update_touch(
    job_id: str,
    *,
    status: Optional[str] = None,
    progress: Optional[int] = None,
    stage: Optional[str] = None,
    message: Optional[str] = None,
    source: Optional[str] = None,
    append_log: Optional[str] = None,
) -> Dict[str, Any]:
    jid = str(job_id or "").strip()
    now = _panel_update_now_text()
    with _PANEL_UPDATE_LOCK:
        job = _PANEL_UPDATE_JOBS.get(jid)
        if not isinstance(job, dict):
            job = {
                "job_id": jid,
                "status": "running",
                "progress": 0,
                "stage": "",
                "message": "",
                "source": "",
                "started_at": now,
                "updated_at": now,
                "finished_at": "",
                "logs": [],
            }
            _PANEL_UPDATE_JOBS[jid] = job

        if status is not None:
            job["status"] = _panel_update_canon_status(status)
        if progress is not None:
            cur = int(job.get("progress") or 0)
            nxt = max(0, min(100, int(progress)))
            if nxt < cur and _panel_update_canon_status(job.get("status")) in _PANEL_UPDATE_ACTIVE_STATES:
                nxt = cur
            job["progress"] = nxt
        if stage is not None:
            job["stage"] = str(stage or "").strip()
        if message is not None:
            job["message"] = str(message or "").strip()
        if source is not None:
            job["source"] = str(source or "").strip()
        if append_log is not None:
            ln = _panel_update_sanitize_line(append_log)
            if ln:
                logs = job.get("logs")
                if not isinstance(logs, list):
                    logs = []
                    job["logs"] = logs
                logs.append(ln)
                if len(logs) > int(_PANEL_UPDATE_LOG_MAX):
                    del logs[: len(logs) - int(_PANEL_UPDATE_LOG_MAX)]

        st_now = _panel_update_canon_status(job.get("status"))
        if st_now in _PANEL_UPDATE_TERMINAL_STATES and not str(job.get("finished_at") or "").strip():
            job["finished_at"] = now
        if st_now == "restarting" and int(job.get("progress") or 0) < 95:
            job["progress"] = 95
        job["updated_at"] = now

        snap = {
            "job_id": str(job.get("job_id") or jid),
            "status": _panel_update_canon_status(job.get("status")),
            "progress": max(0, min(100, int(job.get("progress") or 0))),
            "stage": str(job.get("stage") or "").strip(),
            "message": str(job.get("message") or "").strip(),
            "source": str(job.get("source") or "").strip(),
            "started_at": str(job.get("started_at") or "").strip(),
            "updated_at": str(job.get("updated_at") or "").strip(),
            "finished_at": str(job.get("finished_at") or "").strip(),
            "logs": list(job.get("logs") or []),
        }

    _panel_update_persist(snap)
    return snap


def _panel_update_prune_memory() -> None:
    cutoff = time.time() - float(_PANEL_UPDATE_STALE_SEC)
    drop_ids: List[str] = []
    with _PANEL_UPDATE_LOCK:
        for jid, item in _PANEL_UPDATE_JOBS.items():
            if not isinstance(item, dict):
                drop_ids.append(str(jid))
                continue
            st = _panel_update_canon_status(item.get("status"))
            if st in _PANEL_UPDATE_ACTIVE_STATES:
                continue
            ts = _panel_update_parse_ts(item.get("updated_at"))
            if ts > 0 and ts < cutoff:
                drop_ids.append(str(jid))
        for jid in drop_ids:
            _PANEL_UPDATE_JOBS.pop(jid, None)


def _panel_update_local_script_path() -> str:
    candidates: List[str] = []
    cfg = setting_str("panel_update_script_path", default="", env_names=["REALM_PANEL_UPDATE_SCRIPT"]).strip()
    if cfg:
        candidates.append(cfg)
    try:
        cur = Path(__file__).resolve()
        # /opt/realm-panel/panel/app/routers/api_agents.py -> /opt/realm-panel/realm_panel.sh
        candidates.append(str(cur.parents[4] / "realm_panel.sh"))
        candidates.append(str(cur.parents[3] / "realm_panel.sh"))
    except Exception:
        pass
    candidates.extend(
        [
            "/opt/realm-panel/realm_panel.sh",
            "/usr/local/bin/realm_panel.sh",
        ]
    )
    seen: set[str] = set()
    for p in candidates:
        path = str(p or "").strip()
        if not path or path in seen:
            continue
        seen.add(path)
        try:
            if os.path.isfile(path):
                return path
        except Exception:
            continue
    return ""


def _panel_update_build_command() -> Tuple[str, str]:
    script = _panel_update_local_script_path()
    if script:
        quoted = shlex.quote(script)
        return f"set -euo pipefail; printf '2\\n1\\n' | bash {quoted}", script
    remote = (
        "bash <(curl -fsSL https://nexus.infpro.me/nexus/realm_panel.sh "
        "|| curl -fsSL https://raw.githubusercontent.com/cyeinfpro/NexusControlPlane/main/realm_panel.sh)"
    )
    cmd = "set -euo pipefail; printf '2\\n1\\n' | " + remote
    return cmd, "remote:realm_panel.sh"


def _panel_update_run_worker(job_id: str) -> None:
    global _PANEL_UPDATE_WORKER
    global _PANEL_UPDATE_WORKER_JOB_ID

    jid = str(job_id or "").strip()
    if not jid:
        return

    cmd, source = _panel_update_build_command()
    _panel_update_touch(
        jid,
        status="running",
        progress=2,
        stage="准备执行更新脚本",
        source=source,
        append_log=f"任务启动：{source}",
    )

    proc: Optional[subprocess.Popen[str]] = None
    saw_done = False
    saw_restart = False
    try:
        proc = subprocess.Popen(
            ["bash", "-lc", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        _panel_update_touch(
            jid,
            progress=5,
            stage="更新任务已启动",
            append_log=f"更新命令已启动（pid={int(proc.pid)}）",
        )

        if proc.stdout is not None:
            for raw in proc.stdout:
                line = _panel_update_sanitize_line(raw)
                if not line:
                    continue
                cur = _panel_update_snapshot(jid) or {}
                cur_progress = int(cur.get("progress") or 0)
                cur_stage = str(cur.get("stage") or "").strip()
                next_p, next_stage, hint_status, hint_msg = _panel_update_progress_hint(line, cur_progress, cur_stage)

                if "面板已更新并重启" in line:
                    saw_done = True
                if ("restart realm-panel.service" in line.lower()) or ("systemctl restart realm-panel.service" in line.lower()):
                    saw_restart = True

                _panel_update_touch(
                    jid,
                    status=(hint_status or ("restarting" if saw_restart and next_p >= 92 else None)),
                    progress=next_p,
                    stage=next_stage,
                    message=(hint_msg if hint_msg else None),
                    append_log=line,
                )
    except Exception as exc:
        _panel_update_touch(
            jid,
            status="failed",
            progress=100,
            stage="更新失败",
            message=f"启动更新命令失败：{exc}",
            append_log=f"更新失败：{exc}",
        )
        logger.exception("panel update worker crashed job_id=%s", jid)
        return
    finally:
        try:
            if proc is not None and proc.stdout is not None:
                proc.stdout.close()
        except Exception:
            pass

    rc = -1
    try:
        if proc is not None:
            rc = int(proc.wait(timeout=5))
    except Exception:
        rc = -1

    cur = _panel_update_snapshot(jid) or {}
    cur_progress = int(cur.get("progress") or 0)
    restart_signal_exit = rc in (-15, 143)
    if rc == 0:
        _panel_update_touch(
            jid,
            status="done",
            progress=100,
            stage="更新完成，正在刷新面板",
            message="",
            append_log="更新完成",
        )
    else:
        if saw_done:
            _panel_update_touch(
                jid,
                status="done",
                progress=100,
                stage="更新完成，正在刷新面板",
                message="",
                append_log=f"更新进程退出（code={rc}）",
            )
        elif restart_signal_exit:
            _panel_update_touch(
                jid,
                status="restarting",
                progress=max(96, cur_progress),
                stage="面板服务重启中",
                message="更新进程收到重启信号，等待面板恢复",
                append_log=f"更新进程退出（code={rc}），判定为重启中",
            )
        elif saw_restart or cur_progress >= 90:
            _panel_update_touch(
                jid,
                status="restarting",
                progress=max(95, cur_progress),
                stage="面板服务重启中",
                message="更新已进入重启阶段，等待面板恢复",
                append_log=f"更新进程退出（code={rc}），等待服务恢复",
            )
        else:
            _panel_update_touch(
                jid,
                status="failed",
                progress=100,
                stage="更新失败",
                message=f"更新命令退出码 {rc}",
                append_log=f"更新失败：退出码 {rc}",
            )

    with _PANEL_UPDATE_LOCK:
        if str(_PANEL_UPDATE_WORKER_JOB_ID or "").strip() == jid:
            _PANEL_UPDATE_WORKER_JOB_ID = ""
            _PANEL_UPDATE_WORKER = None


def _panel_update_reconcile(snapshot: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(snapshot, dict):
        return None
    jid = str(snapshot.get("job_id") or "").strip()
    if not jid:
        return snapshot
    st = _panel_update_canon_status(snapshot.get("status"))
    upd_ts = _panel_update_parse_ts(snapshot.get("updated_at"))
    age = max(0.0, time.time() - upd_ts) if upd_ts > 0 else 0.0
    alive = _panel_update_worker_alive(jid)
    progress = int(snapshot.get("progress") or 0)
    message = str(snapshot.get("message") or "").strip()

    if st == "failed" and ("退出码 -15" in message or "退出码 143" in message) and age <= 120.0:
        return _panel_update_touch(
            jid,
            status="restarting",
            progress=max(96, progress),
            stage="面板服务重启中",
            message="检测到更新重启信号，正在等待面板恢复",
            append_log="检测到退出码 -15/143，自动切换为重启等待状态",
        )

    if st == "running" and (not alive):
        if age >= 12.0 and progress >= 65:
            return _panel_update_touch(
                jid,
                status="restarting",
                progress=max(95, progress),
                stage="面板服务重启中",
                message="更新已进入重启阶段，等待面板恢复",
                append_log="检测到更新进程退出，正在等待面板恢复",
            )
        if age >= 20.0 and progress < 65:
            return _panel_update_touch(
                jid,
                status="failed",
                progress=100,
                stage="更新失败",
                message="更新任务中断，请重新发起更新",
                append_log="更新任务异常中断",
            )
        if age >= float(_PANEL_UPDATE_STALE_SEC):
            return _panel_update_touch(
                jid,
                status="failed",
                progress=100,
                stage="更新失败",
                message="更新任务长时间无响应，请重试",
                append_log="更新任务超时",
            )

    if st == "restarting" and (not alive):
        if age >= float(_PANEL_UPDATE_STALE_SEC):
            return _panel_update_touch(
                jid,
                status="failed",
                progress=100,
                stage="更新失败",
                message="面板重启等待超时，请检查服务状态",
                append_log="等待面板恢复超时",
            )
        if age >= 6.0:
            return _panel_update_touch(
                jid,
                status="done",
                progress=100,
                stage="更新完成，正在刷新面板",
                message="",
                append_log="面板服务已恢复，更新任务完成",
            )

    return snapshot


def _panel_update_public(snapshot: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(snapshot, dict):
        return {
            "job_id": "",
            "status": "idle",
            "progress": 0,
            "stage": "",
            "message": "",
            "source": "",
            "started_at": "",
            "updated_at": "",
            "finished_at": "",
            "logs": [],
            "auto_reload": False,
        }
    st = _panel_update_canon_status(snapshot.get("status"))
    return {
        "job_id": str(snapshot.get("job_id") or "").strip(),
        "status": st,
        "progress": max(0, min(100, int(snapshot.get("progress") or 0))),
        "stage": str(snapshot.get("stage") or "").strip(),
        "message": str(snapshot.get("message") or "").strip(),
        "source": str(snapshot.get("source") or "").strip(),
        "started_at": str(snapshot.get("started_at") or "").strip(),
        "updated_at": str(snapshot.get("updated_at") or "").strip(),
        "finished_at": str(snapshot.get("finished_at") or "").strip(),
        "logs": list(snapshot.get("logs") or []),
        "auto_reload": st in ("restarting", "done"),
    }


def _parse_int_env(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return int(default)
    try:
        return int(float(raw))
    except Exception:
        return int(default)


def _parse_float_env(name: str, default: float) -> float:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return float(default)
    try:
        return float(raw)
    except Exception:
        return float(default)


def _coerce_int(raw: Any, default: int = 0) -> int:
    try:
        return int(raw)
    except Exception:
        try:
            return int(float(str(raw).strip()))
        except Exception:
            return int(default)


def _is_storage_mount_site(site: Any) -> bool:
    return str((site or {}).get("type") or "").strip().lower() == "storage_mount"


def _explicit_url_port(raw: Any) -> int:
    s = str(raw or "").strip()
    if not s:
        return 0
    if "://" not in s:
        s = "http://" + s
    try:
        u = urlsplit(s)
        p = int(u.port or 0)
        if p > 0 and p <= 65535:
            return p
    except Exception:
        return 0


_TZ_NAME_RE = re.compile(r"^[A-Za-z0-9._+\-/]{1,128}$")


def _normalize_tz_name(raw: Any, default: str = "Asia/Shanghai") -> str:
    s = str(raw or "").strip()
    if not s:
        return str(default or "Asia/Shanghai")
    if len(s) > 128:
        return str(default or "Asia/Shanghai")
    if not _TZ_NAME_RE.match(s):
        return str(default or "Asia/Shanghai")
    return s


_SITE_TASK_TYPES = {
    "website_env_ensure",
    "website_env_uninstall",
    "website_ssl_issue",
    "website_ssl_renew",
    "create_site",
    "site_update",
    "site_delete",
    "site_file_op",
    "remote_storage_mount",
    "remote_storage_unmount",
    "netmon_probe",
}
_REMOTE_STORAGE_PROFILE_SETTING_KEY = "remote_storage_profiles"
_REMOTE_PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_REMOTE_STORAGE_PASSWORD_KEY_SETTING = "remote_storage_password_key"
_REMOTE_STORAGE_PASSWORD_ENV_KEYS = (
    "REALM_REMOTE_STORAGE_PASSWORD_KEY",
    "REALM_PANEL_SECRET_KEY",
)
_REMOTE_STORAGE_PASSWORD_ENC_PREFIX = "enc:v1:"
_SITE_TASK_MAX_ATTEMPTS = max(1, min(30, _parse_int_env("REALM_WEBSITE_OP_MAX_ATTEMPTS", 10)))
_SITE_TASK_RETRY_BASE_SEC = max(1.0, min(120.0, _parse_float_env("REALM_WEBSITE_OP_RETRY_BASE_SEC", 3.0)))
_SITE_TASK_RETRY_MAX_SEC = max(
    _SITE_TASK_RETRY_BASE_SEC,
    min(600.0, _parse_float_env("REALM_WEBSITE_OP_RETRY_MAX_SEC", 60.0)),
)
_SITE_TASK_RUNNING_REDISPATCH_SEC = max(30.0, min(600.0, _parse_float_env("REALM_WEBSITE_RUNNING_REDISPATCH_SEC", 180.0)))
_NETMON_TASK_RUNNING_REDISPATCH_SEC = max(
    10.0, min(300.0, _parse_float_env("REALM_NETMON_RUNNING_REDISPATCH_SEC", 45.0))
)

_AGENT_UPDATE_MAX_RETRIES = max(1, min(20, _parse_int_env("REALM_AGENT_UPDATE_MAX_RETRIES", 4)))
_AGENT_UPDATE_ACK_TIMEOUT_SEC = max(120.0, min(7200.0, _parse_float_env("REALM_AGENT_UPDATE_ACK_TIMEOUT_SEC", 300.0)))
_AGENT_UPDATE_RUNNING_TIMEOUT_SEC = max(
    600.0, min(172800.0, _parse_float_env("REALM_AGENT_UPDATE_RUNNING_TIMEOUT_SEC", 7200.0))
)
# Legacy/compat delivered 阶段（无 accepted/running 回执）不应沿用完整 running 超时，
# 否则“下一次重试”会被拉到 2 小时以上，用户观感像卡死。
_AGENT_UPDATE_LEGACY_DELIVERED_TIMEOUT_SEC = max(
    120.0, min(7200.0, _parse_float_env("REALM_AGENT_UPDATE_LEGACY_DELIVERED_TIMEOUT_SEC", 600.0))
)
_AGENT_UPDATE_RETRY_BASE_SEC = max(20.0, min(1800.0, _parse_float_env("REALM_AGENT_UPDATE_RETRY_BASE_SEC", 60.0)))
_AGENT_UPDATE_RETRY_MAX_SEC = max(
    _AGENT_UPDATE_RETRY_BASE_SEC, min(21600.0, _parse_float_env("REALM_AGENT_UPDATE_RETRY_MAX_SEC", 3600.0))
)
_AGENT_UPDATE_EARLY_COMPAT_SEC = max(
    20.0, min(3600.0, _parse_float_env("REALM_AGENT_UPDATE_EARLY_COMPAT_SEC", 90.0))
)
_AGENT_UPDATE_REDISPATCH_SEC = max(
    10.0, min(600.0, _parse_float_env("REALM_AGENT_UPDATE_REDISPATCH_SEC", 30.0))
)
_AGENT_UPDATE_OFFLINE_EXPIRE_SEC = max(
    3600.0, min(604800.0, _parse_float_env("REALM_AGENT_UPDATE_OFFLINE_EXPIRE_SEC", 43200.0))
)
_AGENT_REPORT_MAX_COMPRESSED_BYTES = max(
    128 * 1024,
    min(32 * 1024 * 1024, _parse_int_env("REALM_AGENT_REPORT_MAX_COMPRESSED_BYTES", 2 * 1024 * 1024)),
)
_AGENT_REPORT_MAX_DECOMPRESSED_BYTES = max(
    _AGENT_REPORT_MAX_COMPRESSED_BYTES,
    min(64 * 1024 * 1024, _parse_int_env("REALM_AGENT_REPORT_MAX_DECOMPRESSED_BYTES", 12 * 1024 * 1024)),
)


def _remote_profile_id(raw: Any) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    if not _REMOTE_PROFILE_ID_RE.match(s):
        return ""
    return s


def _remote_mount_action_for_type(task_type: str, fallback_action: Any = "") -> str:
    t = str(task_type or "").strip().lower()
    if t == "remote_storage_unmount":
        return "unmount"
    if t == "remote_storage_mount":
        return "mount"
    a = str(fallback_action or "").strip().lower()
    if a in ("mount", "unmount"):
        return a
    return "mount"


def _remote_mount_action_label(action: str) -> str:
    return "卸载" if str(action or "").strip().lower() == "unmount" else "挂载"


def _remote_storage_password_key_bytes() -> bytes:
    raw = str(get_panel_setting(_REMOTE_STORAGE_PASSWORD_KEY_SETTING, "") or "").strip()
    if not raw:
        for env_name in _REMOTE_STORAGE_PASSWORD_ENV_KEYS:
            env_value = str(os.getenv(str(env_name) or "") or "").strip()
            if env_value:
                raw = env_value
                break
    if not raw:
        return b""
    try:
        decoded = base64.urlsafe_b64decode(raw.encode("utf-8"))
        if len(decoded) == 32:
            return raw.encode("utf-8")
    except Exception:
        pass
    return b""


def _remote_storage_decrypt_password(raw: Any) -> str:
    token = str(raw or "").strip()
    if not token:
        return ""
    if token.startswith(_REMOTE_STORAGE_PASSWORD_ENC_PREFIX):
        token = token[len(_REMOTE_STORAGE_PASSWORD_ENC_PREFIX):]
    if not token:
        return ""
    if Fernet is None:
        return ""
    key = _remote_storage_password_key_bytes()
    if not key:
        return ""
    try:
        plain = Fernet(key).decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception):
        return ""
    text = str(plain or "").strip()
    if len(text) > 128:
        text = text[:128]
    return text


def _remote_storage_load_profiles() -> List[Dict[str, Any]]:
    raw = str(get_panel_setting(_REMOTE_STORAGE_PROFILE_SETTING_KEY, "") or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    return [dict(x) for x in data if isinstance(x, dict)]


def _remote_storage_save_profiles(rows: List[Dict[str, Any]]) -> None:
    payload = json.dumps((rows or []), ensure_ascii=False, separators=(",", ":"))
    set_panel_setting(_REMOTE_STORAGE_PROFILE_SETTING_KEY, payload)


def _remote_storage_update_profile_mount(
    profile_id: str,
    action: str,
    ok: bool,
    message: str,
) -> None:
    pid = _remote_profile_id(profile_id)
    if not pid:
        return
    rows = _remote_storage_load_profiles()
    if not rows:
        return
    idx = -1
    row: Dict[str, Any] = {}
    for i, item in enumerate(rows):
        if str((item or {}).get("id") or "").strip() == pid:
            idx = i
            row = item if isinstance(item, dict) else {}
            break
    if idx < 0 or not isinstance(row, dict):
        return
    act = str(action or "mount").strip().lower()
    now_text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = str(message or "").strip() or (
        f"{_remote_mount_action_label(act)}成功" if bool(ok) else f"{_remote_mount_action_label(act)}失败"
    )
    if len(msg) > 280:
        msg = msg[:279] + "…"
    row["last_sync_at"] = now_text
    row["updated_at"] = now_text
    row["mount_message"] = msg
    if bool(ok):
        if act == "unmount":
            row["mount_status"] = "unmounted"
            row["mounted_at"] = ""
        else:
            row["mount_status"] = "mounted"
            row["mounted_at"] = now_text
    else:
        row["mount_status"] = "error"
    rows[idx] = row
    rows.sort(key=lambda x: str((x or {}).get("updated_at") or ""), reverse=True)
    _remote_storage_save_profiles(rows)


class _RequestBodyTooLargeError(RuntimeError):
    pass


def _gunzip_limited(raw: bytes, max_decompressed: int) -> bytes:
    """Decompress gzip payload with an output cap to avoid memory spikes."""
    limit = max(1, int(max_decompressed or 1))
    out = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(raw or b"")) as gz:
        while True:
            remain = limit - len(out)
            if remain <= 0:
                raise _RequestBodyTooLargeError("decompressed body too large")
            # Read at most remain+1 bytes so overflow can be detected deterministically.
            chunk = gz.read(min(64 * 1024, remain + 1))
            if not chunk:
                break
            out.extend(chunk)
            if len(out) > limit:
                raise _RequestBodyTooLargeError("decompressed body too large")
    return bytes(out)


_AGENT_REASON_TEXT = {
    "unsupported_agent_protocol": "节点 Agent 不支持更新协议 v2（缺少 command_id/accepted 回执）。",
    "ack_timeout": "等待节点确认超时，已进入退避重试。",
    "ack_timeout_exhausted": "等待节点确认超时，且重试次数已耗尽。",
    "running_timeout": "安装执行超时，已进入退避重试。",
    "running_timeout_exhausted": "安装执行超时，且重试次数已耗尽。",
    "download_error": "下载更新文件失败（主备地址均不可用）。",
    "installer_error": "安装脚本执行失败。",
    "update_cmd_exception": "更新命令处理异常。",
    "invalid_command": "更新命令参数不合法。",
    "missing_systemd_run": "节点缺少 systemd-run，无法安全执行自更新。",
    "signature_rejected": "更新命令签名校验失败（可能是节点时间偏移或密钥不一致）。",
    "offline_timeout": "节点长期离线，更新任务已过期。",
    "agent_failed": "节点执行更新失败。",
    "retry_exhausted": "节点多次执行失败，已达到最大重试次数。",
}

_AGENT_TERMINAL_FAIL_REASONS = {
    "invalid_command",
    "missing_systemd_run",
    "unsupported_agent_protocol",
}


def _fmt_dt(ts: float) -> str:
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")


def _parse_dt(v: Any) -> float:
    s = str(v or "").strip()
    if not s:
        return 0.0
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").timestamp()
    except Exception:
        return 0.0


def _valid_dt_str(v: Any, fallback: str) -> str:
    s = str(v or "").strip()
    if not s:
        return fallback
    try:
        datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        return s
    except Exception:
        return fallback


def _canon_agent_update_state(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    if s in ("queued", "pending"):
        return "queued"
    if s in ("sent", "delivered"):
        return "delivered"
    if s == "accepted":
        return "accepted"
    if s in ("installing", "running"):
        return "running"
    if s == "retrying":
        return "retrying"
    if s in ("done", "success"):
        return "done"
    if s in ("failed", "error"):
        return "failed"
    if s in ("expired", "timeout"):
        return "expired"
    return s or "queued"


def _agent_retry_backoff_sec(next_attempt_no: int) -> float:
    n = max(1, int(next_attempt_no or 1))
    return float(min(_AGENT_UPDATE_RETRY_MAX_SEC, _AGENT_UPDATE_RETRY_BASE_SEC * (2 ** (n - 1))))


def _to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, (int, float)):
        return bool(int(v))
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on", "y"):
        return True
    if s in ("0", "false", "no", "off", "n", ""):
        return False
    return False


def _infer_agent_cmd_ts_candidates(report: Any, fallback_ts: float) -> List[int]:
    """Infer candidate command timestamps from agent-reported wall clock.

    Returns a candidate list sorted by proximity to panel-now. This allows
    robust retries for legacy agents with unknown timezone + clock drift.
    """
    fb = int(fallback_ts or time.time())
    if not isinstance(report, dict):
        return [fb]
    raw = ""
    try:
        raw = str(
            report.get("time")
            or ((report.get("info") or {}).get("time") if isinstance(report.get("info"), dict) else "")
            or ""
        ).strip()
    except Exception:
        raw = ""
    if not raw:
        return [fb]
    try:
        dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        base_utc = int(calendar.timegm(dt.timetuple()))
        now_i = int(fallback_ts or time.time())
        arr: List[Tuple[int, int]] = []
        for off_min in range(-14 * 60, 14 * 60 + 1, 30):
            cand = int(base_utc - off_min * 60)
            arr.append((abs(cand - now_i), cand))
        arr.sort(key=lambda x: x[0])
        out: List[int] = []
        seen: set[int] = set()
        for _, cand in arr:
            if cand in seen:
                continue
            seen.add(cand)
            out.append(int(cand))
        if not out:
            out = [fb]
        return out
    except Exception:
        return [fb]


def _normalize_agent_caps(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, Any] = {}
    proto_raw = raw.get("update_protocol_version", raw.get("update_protocol"))
    try:
        proto = int(proto_raw)
    except Exception:
        proto = 0
    supports_cmd_id = _to_bool(raw.get("supports_update_command_id"))
    supports_ack = _to_bool(raw.get("supports_update_accept_ack"))
    supports_reason = _to_bool(raw.get("supports_update_reason_code"))
    if proto >= 2:
        supports_cmd_id = True
        supports_ack = True
        supports_reason = True
    out["update_protocol_version"] = int(proto)
    out["supports_update_command_id"] = bool(supports_cmd_id)
    out["supports_update_accept_ack"] = bool(supports_ack)
    out["supports_update_reason_code"] = bool(supports_reason)
    return out


def _supports_update_v2(caps: Dict[str, Any]) -> bool:
    if not isinstance(caps, dict):
        return False
    proto = 0
    try:
        proto = int(caps.get("update_protocol_version") or 0)
    except Exception:
        proto = 0
    if proto >= 2:
        return True
    return _to_bool(caps.get("supports_update_command_id")) and _to_bool(caps.get("supports_update_accept_ack"))


def _reason_text(code: Any) -> str:
    k = str(code or "").strip().lower()
    if not k:
        return ""
    return str(_AGENT_REASON_TEXT.get(k) or "")


def _is_terminal_fail_reason(code: Any) -> bool:
    k = str(code or "").strip().lower()
    if not k:
        return False
    return k in _AGENT_TERMINAL_FAIL_REASONS


def _infer_agent_fail_reason(rep_reason: Any, rep_msg: Any) -> str:
    reason = str(rep_reason or "").strip().lower()
    if reason:
        return reason
    msg = str(rep_msg or "").strip().lower()
    if not msg:
        return "agent_failed"
    if "systemd-run" in msg or "missing_systemd_run" in msg:
        return "missing_systemd_run"
    if "签名校验失败" in msg or "signature" in msg:
        return "signature_rejected"
    if "invalid command" in msg or "缺少必要参数" in msg or "invalid_command" in msg:
        return "invalid_command"
    if "download" in msg or "下载" in msg:
        return "download_error"
    if "curl" in msg or "sha256" in msg or "zip" in msg:
        return "installer_error"
    if "timeout" in msg:
        return "running_timeout"
    return "agent_failed"

_ENV_CAP_ALIAS = {
    "nginx": "nginx",
    "php": "php-fpm",
    "php-fpm": "php-fpm",
    "phpfpm": "php-fpm",
    "acme": "acme.sh",
    "acme.sh": "acme.sh",
}


def _site_task_backoff_sec(attempt_no: int) -> float:
    n = max(1, int(attempt_no or 1))
    return float(min(_SITE_TASK_RETRY_MAX_SEC, _SITE_TASK_RETRY_BASE_SEC * (2 ** (n - 1))))


def _site_task_progress_for_attempt(attempt_no: int, max_attempts: int) -> int:
    total = max(1, int(max_attempts or 1))
    cur = max(1, min(total, int(attempt_no or 1)))
    if total <= 1:
        return 10
    ratio = float(cur - 1) / float(total - 1)
    return max(8, min(90, int(8 + ratio * 72)))


def _site_task_max_attempts(task: Dict[str, Any]) -> int:
    payload = task.get("payload") if isinstance(task, dict) else None
    raw = None
    if isinstance(payload, dict):
        raw = payload.get("max_attempts")
    try:
        val = int(raw) if raw is not None else int(_SITE_TASK_MAX_ATTEMPTS)
    except Exception:
        val = int(_SITE_TASK_MAX_ATTEMPTS)
    return max(1, min(30, val))


def _site_task_current_attempt(task: Dict[str, Any]) -> int:
    result = task.get("result") if isinstance(task, dict) else None
    if not isinstance(result, dict):
        return 0
    raw = result.get("attempt")
    if raw is None:
        raw = result.get("attempts")
    try:
        val = int(raw or 0)
    except Exception:
        val = 0
    return max(0, val)


def _site_task_retry_ready(task: Dict[str, Any], now_ts: float) -> bool:
    result = task.get("result") if isinstance(task, dict) else None
    if not isinstance(result, dict):
        return True
    try:
        next_retry_ts = float(result.get("next_retry_ts") or 0.0)
    except Exception:
        next_retry_ts = 0.0
    return next_retry_ts <= 0.0 or now_ts >= next_retry_ts


def _site_task_last_dispatched_ts(task: Dict[str, Any]) -> float:
    result = task.get("result") if isinstance(task, dict) else None
    if not isinstance(result, dict):
        return 0.0
    try:
        return float(result.get("last_dispatched_ts") or 0.0)
    except Exception:
        return 0.0


def _site_task_supersede_remote_mount(task: Dict[str, Any], reason: str) -> None:
    task_id = _coerce_int((task or {}).get("id"), 0)
    if task_id <= 0:
        return
    t = str((task or {}).get("type") or "").strip().lower()
    payload = (task or {}).get("payload") if isinstance((task or {}).get("payload"), dict) else {}
    profile_id = _remote_profile_id(payload.get("profile_id"))
    result_payload = (task or {}).get("result") if isinstance((task or {}).get("result"), dict) else {}
    result_payload = dict(result_payload)
    result_payload.update(
        {
            "op": t or "remote_storage_mount",
            "profile_id": profile_id,
            "superseded": True,
            "superseded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    )
    update_task(
        int(task_id),
        status="failed",
        progress=100,
        error=str(reason or "已被新任务替代"),
        result=result_payload,
    )


def _normalize_proxy_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if t.startswith("unix:"):
        return t
    if "://" in t:
        return t
    return f"http://{t}"


def _is_ssl_renew_skip_error(err: Any) -> bool:
    msg = str(err or "").strip().lower()
    if not msg:
        return False
    signs = (
        "domains not changed",
        "next renewal time is",
        "force renewal",
        "--force",
        "not yet time to renew",
        "skip, next renewal time is",
        "skipping. next renewal time is",
    )
    return any(s in msg for s in signs)


def _remote_mount_retryable_error(err: Any) -> bool:
    msg = str(err or "").strip().lower()
    if not msg:
        return True
    non_retry_signals = (
        "file exists",
        "operation not permitted",
        "permission denied",
        "access denied",
        "authentication",
        "auth failed",
        "invalid argument",
        "挂载点目录非空",
        "挂载点必须是绝对路径",
        "协议不受支持",
        "缺少挂载命令",
    )
    if any(s in msg for s in non_retry_signals):
        return False
    return True


def _node_root_base(node: Dict[str, Any]) -> str:
    return str((node or {}).get("website_root_base") or "").strip()


def _normalize_env_cap_name(raw: Any) -> str:
    k = str(raw or "").strip().lower()
    if not k:
        return ""
    return _ENV_CAP_ALIAS.get(k, k)


def _merge_node_env_caps(node: Dict[str, Any], env_data: Any) -> None:
    if not isinstance(node, dict) or not isinstance(env_data, dict):
        return
    caps = node.get("capabilities")
    merged: Dict[str, Any] = dict(caps) if isinstance(caps, dict) else {}
    changed = False
    for key in ("installed", "already"):
        rows = env_data.get(key)
        if not isinstance(rows, list):
            continue
        for item in rows:
            cap = _normalize_env_cap_name(item)
            if not cap:
                continue
            if not bool(merged.get(cap)):
                merged[cap] = True
                changed = True
    if not changed:
        return
    try:
        update_node_basic(
            int(node.get("id") or 0),
            str(node.get("name") or ""),
            str(node.get("base_url") or ""),
            str(node.get("api_key") or ""),
            verify_tls=bool(node.get("verify_tls")),
            is_private=bool(node.get("is_private")),
            group_name=str(node.get("group_name") or "默认分组"),
            capabilities=merged,
            website_root_base=str(node.get("website_root_base") or "").strip(),
        )
    except Exception:
        pass


def _netmon_payload_mids_by_target(payload: Dict[str, Any]) -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {}
    rows = payload.get("mids_by_target") if isinstance(payload, dict) else {}
    if not isinstance(rows, dict):
        return out
    for key, val in rows.items():
        target = str(key or "").strip()
        if not target:
            continue
        mids: List[int] = []
        arr = val if isinstance(val, list) else []
        for x in arr:
            try:
                mid = int(x)
            except Exception:
                continue
            if mid > 0 and mid not in mids:
                mids.append(mid)
        if mids:
            out[target] = mids
    return out


def _netmon_payload_monitor_ids(payload: Dict[str, Any]) -> List[int]:
    mids: List[int] = []
    for arr in _netmon_payload_mids_by_target(payload).values():
        for mid in arr:
            if mid > 0 and mid not in mids:
                mids.append(mid)
    return mids


def _netmon_touch_monitor_last_run(payload: Dict[str, Any], msg: str, ts_ms: Optional[int] = None) -> None:
    mids = _netmon_payload_monitor_ids(payload if isinstance(payload, dict) else {})
    if not mids:
        return
    now_ms = int(time.time() * 1000)
    ts = int(ts_ms) if ts_ms is not None else now_ms
    for mid in mids:
        try:
            update_netmon_monitor(int(mid), last_run_ts_ms=int(ts), last_run_msg=str(msg or ""))
        except Exception:
            continue


def _site_event_action(task_type: str) -> str:
    if task_type == "website_ssl_issue":
        return "ssl_issue"
    if task_type == "website_ssl_renew":
        return "ssl_renew"
    if task_type == "create_site":
        return "site_create"
    return task_type


def _site_task_final_fail(node: Dict[str, Any], task: Dict[str, Any], err_text: str, attempt: int) -> None:
    task_id = int(task.get("id") or 0)
    t = str(task.get("type") or "").strip().lower()
    payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
    max_attempts = _site_task_max_attempts(task)
    result_payload = {
        "op": t,
        "attempt": int(attempt),
        "attempts": int(attempt),
        "max_attempts": int(max_attempts),
        "reported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    update_task(task_id, status="failed", progress=100, error=str(err_text or ""), result=result_payload)

    if t == "netmon_probe":
        _netmon_touch_monitor_last_run(payload, "dispatch_failed")
        return

    if t == "create_site":
        site_id = _coerce_int(payload.get("site_id"), 0) if isinstance(payload, dict) else 0
        if site_id > 0:
            try:
                update_site(int(site_id), status="error")
            except Exception:
                pass
            add_site_event(
                int(site_id),
                "site_create",
                status="failed",
                actor="agent",
                error=str(err_text or ""),
                payload={"task_id": int(task_id), "attempt": int(attempt)},
            )
        return

    if t == "site_update":
        site_id = _coerce_int(payload.get("site_id"), 0) if isinstance(payload, dict) else 0
        if site_id > 0:
            add_site_event(
                int(site_id),
                "site_update",
                status="failed",
                actor="agent",
                error=str(err_text or ""),
                payload={"task_id": int(task_id), "attempt": int(attempt)},
            )
        return

    if t == "site_delete":
        site_id = _coerce_int(payload.get("site_id"), 0) if isinstance(payload, dict) else 0
        if site_id > 0:
            add_site_event(
                int(site_id),
                "site_delete",
                status="failed",
                actor="agent",
                error=str(err_text or ""),
                payload={"task_id": int(task_id), "attempt": int(attempt)},
            )
        return

    if t == "site_file_op":
        site_id = _coerce_int(payload.get("site_id"), 0) if isinstance(payload, dict) else 0
        action = str(payload.get("action") or "").strip().lower() if isinstance(payload, dict) else ""
        if site_id > 0 and action:
            add_site_event(
                int(site_id),
                f"site_file_{action}",
                status="failed",
                actor="agent",
                error=str(err_text or ""),
                payload={"task_id": int(task_id), "attempt": int(attempt)},
            )
        return

    if t in ("remote_storage_mount", "remote_storage_unmount"):
        profile_id = _remote_profile_id((payload or {}).get("profile_id"))
        act = _remote_mount_action_for_type(t, (payload or {}).get("action"))
        _remote_storage_update_profile_mount(profile_id, act, False, str(err_text or "任务执行失败"))
        return

    if t in ("website_ssl_issue", "website_ssl_renew"):
        site_id = _coerce_int(payload.get("site_id"), 0) if isinstance(payload, dict) else 0
        cert_id = _coerce_int(payload.get("cert_id"), 0) if isinstance(payload, dict) else 0
        if cert_id > 0:
            update_certificate(int(cert_id), status="failed", last_error=str(err_text or ""))
        else:
            site = get_site(int(site_id)) if site_id > 0 else None
            domains = list(site.get("domains") or []) if isinstance(site, dict) else []
            node_id = int((site or {}).get("node_id") or int(node.get("id") or 0))
            if node_id > 0 and domains:
                add_certificate(
                    node_id=node_id,
                    site_id=int(site_id) if site_id > 0 else None,
                    domains=domains,
                    status="failed",
                    last_error=str(err_text or ""),
                )
        if site_id > 0:
            add_site_event(
                int(site_id),
                _site_event_action(t),
                status="failed",
                actor="agent",
                error=str(err_text or ""),
                payload={"task_id": int(task_id), "attempt": int(attempt)},
            )


def _site_task_retry(node: Dict[str, Any], task: Dict[str, Any], err_text: str, attempt: int) -> None:
    task_id = int(task.get("id") or 0)
    t = str(task.get("type") or "").strip().lower()
    max_attempts = _site_task_max_attempts(task)
    backoff = _site_task_backoff_sec(int(attempt))
    next_retry_ts = float(time.time() + backoff)
    result_payload = {
        "op": t,
        "attempt": int(attempt),
        "max_attempts": int(max_attempts),
        "retry_in_sec": float(backoff),
        "next_retry_ts": float(next_retry_ts),
        "reported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    update_task(
        task_id,
        status="queued",
        progress=_site_task_progress_for_attempt(int(attempt), int(max_attempts)),
        error=str(err_text or ""),
        result=result_payload,
    )
    payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
    if t == "netmon_probe":
        _netmon_touch_monitor_last_run(payload, "dispatch_retrying")
        return
    if t in ("remote_storage_mount", "remote_storage_unmount"):
        profile_id = _remote_profile_id((payload or {}).get("profile_id"))
        act = _remote_mount_action_for_type(t, (payload or {}).get("action"))
        retry_msg = f"{_remote_mount_action_label(act)}失败，{int(max(1.0, backoff))} 秒后重试：{str(err_text or '').strip() or '任务执行失败'}"
        _remote_storage_update_profile_mount(profile_id, act, False, retry_msg)
        return
    if t in ("website_ssl_issue", "website_ssl_renew"):
        cert_id = _coerce_int(payload.get("cert_id"), 0)
        if cert_id > 0:
            update_certificate(int(cert_id), status="pending", last_error=str(err_text or ""))


def _site_task_mark_success(node: Dict[str, Any], task: Dict[str, Any], result_data: Dict[str, Any], attempt: int) -> None:
    task_id = int(task.get("id") or 0)
    t = str(task.get("type") or "").strip().lower()
    payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
    max_attempts = _site_task_max_attempts(task)
    result_payload = dict(result_data or {})
    result_payload["attempt"] = int(attempt)
    result_payload["attempts"] = int(attempt)
    result_payload["max_attempts"] = int(max_attempts)
    result_payload["reported_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    node_id = int(node.get("id") or 0)
    if t == "netmon_probe":
        ts_ms = int(time.time() * 1000)
        try:
            ts_ms = int(result_payload.get("ts") or result_payload.get("ts_ms") or payload.get("queued_ts_ms") or ts_ms)
        except Exception:
            ts_ms = int(time.time() * 1000)

        mids_map = _netmon_payload_mids_by_target(payload)
        result_map = result_payload.get("results") if isinstance(result_payload.get("results"), dict) else {}
        rows: List[Tuple[int, int, int, int, Optional[float], Optional[str]]] = []
        mon_state: Dict[int, Dict[str, Any]] = {}

        for target, mids in mids_map.items():
            item = result_map.get(target) if isinstance(result_map, dict) else None
            if isinstance(item, dict) and bool(item.get("ok")):
                try:
                    latency = float(item.get("latency_ms")) if item.get("latency_ms") is not None else None
                except Exception:
                    latency = None
                for mid in mids:
                    mid_i = int(mid)
                    if mid_i <= 0:
                        continue
                    st = mon_state.get(mid_i)
                    if not st:
                        st = {"ok_any": False, "err": ""}
                        mon_state[mid_i] = st
                    st["ok_any"] = True
                    rows.append((mid_i, int(node_id), int(ts_ms), 1, latency, None))
                continue

            err = ""
            if isinstance(item, dict):
                err = str(item.get("error") or "probe_failed")
            else:
                err = "no_data"
            if len(err) > 200:
                err = err[:200] + "…"
            for mid in mids:
                mid_i = int(mid)
                if mid_i <= 0:
                    continue
                st = mon_state.get(mid_i)
                if not st:
                    st = {"ok_any": False, "err": ""}
                    mon_state[mid_i] = st
                if not st.get("err"):
                    st["err"] = err
                rows.append((mid_i, int(node_id), int(ts_ms), 0, None, err))

        inserted = 0
        try:
            if rows:
                inserted = int(insert_netmon_samples(rows) or 0)
        except Exception:
            inserted = 0

        for mid, st in mon_state.items():
            try:
                msg = "ok" if bool(st.get("ok_any")) else str(st.get("err") or "failed")
                update_netmon_monitor(int(mid), last_run_ts_ms=int(ts_ms), last_run_msg=msg)
            except Exception:
                continue

        result_payload["inserted_samples"] = int(inserted)
        result_payload["monitor_count"] = int(len(mon_state))
        update_task(task_id, status="success", progress=100, error="", result=result_payload)
        return

    if t == "create_site":
        site_id = _coerce_int(payload.get("site_id"), 0) if isinstance(payload, dict) else 0
        health = result_payload.get("health") if isinstance(result_payload.get("health"), dict) else {}
        health_status = "unknown"
        health_error = ""
        health_code = 0
        health_latency = 0
        if isinstance(health, dict) and health:
            try:
                health_code = int(health.get("status_code") or 0)
            except Exception:
                health_code = 0
            try:
                health_latency = int(health.get("latency_ms") or 0)
            except Exception:
                health_latency = 0
            if bool(health.get("ok")):
                health_status = "ok"
                health_error = ""
            else:
                health_status = "fail"
                health_error = str(health.get("error") or "")

        if site_id > 0:
            try:
                update_site(int(site_id), status="running" if health_status != "fail" else "error")
            except Exception:
                pass
            try:
                update_site_health(
                    int(site_id),
                    health_status,
                    health_code=health_code,
                    health_latency_ms=health_latency,
                    health_error=str(health_error or ""),
                )
            except Exception:
                pass
            add_site_event(
                int(site_id),
                "site_create",
                status="success",
                actor="agent",
                result=result_payload,
                payload={"task_id": int(task_id), "attempt": int(attempt)},
            )
        update_task(task_id, status="success", progress=100, error="", result=result_payload)
        return

    if t == "site_update":
        site_id = _coerce_int(payload.get("site_id"), 0) if isinstance(payload, dict) else 0
        domains = payload.get("domains") if isinstance(payload.get("domains"), list) else []
        domains = [str(x).strip() for x in domains if str(x).strip()]
        if not domains:
            site_obj = get_site(int(site_id)) if site_id > 0 else None
            domains = list(site_obj.get("domains") or []) if isinstance(site_obj, dict) else []
        site_type = str(payload.get("site_type") or "static").strip().lower()
        if site_type not in ("static", "php", "reverse_proxy"):
            site_type = "static"
        root_path = str(payload.get("root_path") or "")
        proxy_target = _normalize_proxy_target(payload.get("proxy_target") or "")
        name = str(payload.get("name") or (domains[0] if domains else f"站点#{site_id}")).strip()
        https_flag = bool(payload.get("https_redirect"))
        gzip_flag = bool(payload.get("gzip_enabled"))
        nginx_tpl = str(payload.get("nginx_tpl") or "")

        health = result_payload.get("health") if isinstance(result_payload.get("health"), dict) else {}
        health_status = "unknown"
        health_error = ""
        health_code = 0
        health_latency = 0
        if isinstance(health, dict) and health:
            try:
                health_code = int(health.get("status_code") or 0)
            except Exception:
                health_code = 0
            try:
                health_latency = int(health.get("latency_ms") or 0)
            except Exception:
                health_latency = 0
            if bool(health.get("ok")):
                health_status = "ok"
            else:
                health_status = "fail"
                health_error = str(health.get("error") or "")

        if site_id > 0:
            try:
                update_site(
                    int(site_id),
                    name=name,
                    domains=domains,
                    site_type=site_type,
                    root_path=root_path if site_type != "reverse_proxy" else (root_path or ""),
                    proxy_target=proxy_target,
                    https_redirect=https_flag,
                    gzip_enabled=gzip_flag,
                    nginx_tpl=nginx_tpl,
                    status="running" if health_status != "fail" else "error",
                )
            except Exception:
                pass

            try:
                update_site_health(
                    int(site_id),
                    health_status,
                    health_code=health_code,
                    health_latency_ms=health_latency,
                    health_error=str(health_error or ""),
                )
            except Exception:
                pass

            try:
                old_domains = payload.get("old_domains") if isinstance(payload.get("old_domains"), list) else []

                def _nd(v: Any) -> str:
                    return str(v or "").strip().lower().strip(".")

                old_set = {_nd(x) for x in old_domains if _nd(x)}
                new_set = {_nd(x) for x in domains if _nd(x)}
                if old_set != new_set:
                    certs = list_certificates(site_id=int(site_id))
                    if certs:
                        update_certificate(
                            int(certs[0].get("id") or 0),
                            domains=domains,
                            status="pending",
                            last_error="站点域名已变更，建议重新申请/续期 SSL 证书",
                        )
            except Exception:
                pass

            add_site_event(
                int(site_id),
                "site_update",
                status="success",
                actor="agent",
                result=result_payload,
                payload={"task_id": int(task_id), "attempt": int(attempt)},
            )

        update_task(task_id, status="success", progress=100, error="", result=result_payload)
        return

    if t == "site_delete":
        site_id = _coerce_int(payload.get("site_id"), 0) if isinstance(payload, dict) else 0
        if site_id > 0:
            try:
                delete_certificates_by_site(int(site_id))
            except Exception:
                pass
            try:
                delete_site_events(int(site_id))
            except Exception:
                pass
            try:
                delete_site_checks(int(site_id))
            except Exception:
                pass
            try:
                delete_site(int(site_id))
            except Exception:
                pass
        update_task(task_id, status="success", progress=100, error="", result=result_payload)
        return

    if t == "site_file_op":
        site_id = _coerce_int(payload.get("site_id"), 0) if isinstance(payload, dict) else 0
        action = str(payload.get("action") or "").strip().lower() if isinstance(payload, dict) else ""
        if site_id > 0 and action:
            add_site_event(
                int(site_id),
                f"site_file_{action}",
                status="success",
                actor="agent",
                result=result_payload,
                payload={"task_id": int(task_id), "attempt": int(attempt)},
            )
        update_task(task_id, status="success", progress=100, error="", result=result_payload)
        return

    if t in ("remote_storage_mount", "remote_storage_unmount"):
        profile_id = _remote_profile_id((payload or {}).get("profile_id"))
        act = _remote_mount_action_for_type(t, (payload or {}).get("action"))
        msg_text = str(
            result_payload.get("msg")
            or result_payload.get("message")
            or result_payload.get("detail")
            or f"{_remote_mount_action_label(act)}成功"
        ).strip()
        _remote_storage_update_profile_mount(profile_id, act, True, msg_text)
        update_task(task_id, status="success", progress=100, error="", result=result_payload)
        return

    update_task(task_id, status="success", progress=100, error="", result=result_payload)

    if t == "website_env_ensure":
        _merge_node_env_caps(node, result_payload)
        return
    if t == "website_env_uninstall":
        if bool(payload.get("purge_data")) and node_id > 0:
            delete_certificates_by_node(node_id)
            try:
                rows = list_sites(node_id=node_id)
            except Exception:
                rows = []
            for s in rows:
                if not isinstance(s, dict) or _is_storage_mount_site(s):
                    continue
                sid = _coerce_int(s.get("id"), 0)
                if sid <= 0:
                    continue
                try:
                    delete_site(int(sid))
                except Exception:
                    pass
        return
    if t not in ("website_ssl_issue", "website_ssl_renew"):
        return

    site_id = _coerce_int(payload.get("site_id"), 0)
    cert_id = _coerce_int(payload.get("cert_id"), 0)
    site = get_site(int(site_id)) if site_id > 0 else None
    domains = result_payload.get("domains")
    if not isinstance(domains, list):
        domains = list(site.get("domains") or []) if isinstance(site, dict) else []
    if cert_id > 0:
        update_certificate(
            int(cert_id),
            status="valid",
            domains=list(domains or []),
            not_before=result_payload.get("not_before"),
            not_after=result_payload.get("not_after"),
            renew_at=result_payload.get("renew_at"),
            last_error="",
        )
    elif node_id > 0 and domains:
        add_certificate(
            node_id=node_id,
            site_id=int(site_id) if site_id > 0 else None,
            domains=list(domains),
            status="valid",
            not_before=result_payload.get("not_before"),
            not_after=result_payload.get("not_after"),
            renew_at=result_payload.get("renew_at"),
            last_error="",
        )

    if site_id > 0:
        add_site_event(
            int(site_id),
            _site_event_action(t),
            status="success",
            actor="agent",
            result=result_payload,
            payload={"task_id": int(task_id), "attempt": int(attempt)},
        )


def _apply_site_task_result(node: Dict[str, Any], row: Dict[str, Any]) -> None:
    task_id = int(row.get("task_id") or 0)
    if task_id <= 0:
        return
    task = get_task(task_id)
    if not isinstance(task, dict):
        return
    node_id = int(node.get("id") or 0)
    if int(task.get("node_id") or 0) != node_id:
        return

    t = str(task.get("type") or "").strip().lower()
    if t not in _SITE_TASK_TYPES:
        return

    current_status = str(task.get("status") or "").strip().lower()
    if current_status in ("success", "failed"):
        return

    result_data = row.get("result")
    if not isinstance(result_data, dict):
        result_data = {}
    err_text = str(row.get("error") or result_data.get("error") or "").strip()
    ok = bool(row.get("ok"))
    if ok and result_data.get("ok") is False:
        ok = False
        if not err_text:
            err_text = str(result_data.get("error") or "").strip()
    if (not ok) and t == "website_ssl_renew" and _is_ssl_renew_skip_error(err_text):
        # Compatibility for older agents: treat acme "renew skipped (not due yet)" as success.
        ok = True
        err_text = ""
        if not isinstance(result_data, dict):
            result_data = {}
        result_data["ok"] = True
        result_data["renew_skipped"] = True
        if not str(result_data.get("message") or "").strip():
            result_data["message"] = "证书未到续期时间，已保持当前证书"
        result_data.pop("error", None)

    try:
        attempt = int(row.get("attempt") or 0)
    except Exception:
        attempt = 0
    if attempt <= 0:
        attempt = max(1, _site_task_current_attempt(task))

    max_attempts = _site_task_max_attempts(task)
    if ok:
        _site_task_mark_success(node, task, result_data, attempt)
        return
    if t in ("remote_storage_mount", "remote_storage_unmount") and not _remote_mount_retryable_error(err_text):
        _site_task_final_fail(node, task, err_text or "任务执行失败", attempt)
        return
    if attempt >= max_attempts:
        _site_task_final_fail(node, task, err_text or "任务执行失败", attempt)
        return
    _site_task_retry(node, task, err_text or "任务执行失败", attempt)


def _ingest_site_task_results(node: Dict[str, Any], rows: Any) -> None:
    if not isinstance(rows, list) or not rows:
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            _apply_site_task_result(node, row)
        except Exception:
            continue


def _build_website_cmd(task: Dict[str, Any], node: Dict[str, Any], attempt: int) -> Tuple[Optional[Dict[str, Any]], str]:
    t = str(task.get("type") or "").strip().lower()
    task_id = int(task.get("id") or 0)
    payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
    node_id = int(node.get("id") or 0)
    if t == "netmon_probe":
        mode = str(payload.get("mode") or "ping").strip().lower()
        if mode not in ("ping", "tcping"):
            mode = "ping"
        try:
            tcp_port = int(payload.get("tcp_port") or 443)
        except Exception:
            tcp_port = 443
        if tcp_port < 1 or tcp_port > 65535:
            tcp_port = 443
        try:
            timeout_f = float(payload.get("timeout") or 1.5)
        except Exception:
            timeout_f = 1.5
        if timeout_f < 0.2:
            timeout_f = 0.2
        if timeout_f > 10.0:
            timeout_f = 10.0
        targets_raw = payload.get("targets") if isinstance(payload.get("targets"), list) else []
        targets: List[str] = []
        for x in targets_raw:
            s = str(x or "").strip()
            if not s:
                continue
            if len(s) > 128:
                continue
            if s not in targets:
                targets.append(s)
        targets = targets[:50]
        if not targets:
            return None, "netmon targets 为空"
        if not _netmon_payload_mids_by_target(payload):
            return None, "netmon mids_by_target 无效"
        return {
            "type": "netmon_probe",
            "task_id": int(task_id),
            "attempt": int(attempt),
            "mode": mode,
            "targets": targets,
            "tcp_port": int(tcp_port),
            "timeout": float(timeout_f),
        }, ""

    if t == "create_site":
        site_id = _coerce_int(payload.get("site_id"), 0)
        if site_id <= 0:
            return None, "site_id 无效"
        site = get_site(int(site_id))
        if not isinstance(site, dict):
            return None, "站点不存在"
        if int(site.get("node_id") or 0) != node_id:
            return None, "站点与节点不匹配"
        domains = [str(x).strip() for x in (site.get("domains") or []) if str(x).strip()]
        if not domains:
            return None, "站点域名为空"
        site_type = str(site.get("type") or "static").strip().lower()
        if site_type not in ("static", "php", "reverse_proxy"):
            site_type = "static"
        proxy_target = _normalize_proxy_target(site.get("proxy_target") or "")
        if site_type == "reverse_proxy" and not proxy_target:
            return None, "反向代理必须填写目标地址"
        req_payload = {
            "name": str(site.get("name") or domains[0]),
            "domains": domains,
            "root_path": str(site.get("root_path") or ""),
            "type": site_type,
            "web_server": str(site.get("web_server") or "nginx"),
            "proxy_target": proxy_target,
            "https_redirect": bool(site.get("https_redirect") or False),
            "gzip_enabled": True if site.get("gzip_enabled") is None else bool(site.get("gzip_enabled")),
            "nginx_tpl": str(site.get("nginx_tpl") or ""),
            "root_base": _node_root_base(node),
        }
        return {
            "type": "create_site",
            "task_id": int(task_id),
            "site_id": int(site_id),
            "attempt": int(attempt),
            "request": req_payload,
        }, ""

    if t == "site_update":
        site_id = _coerce_int(payload.get("site_id"), 0)
        if site_id <= 0:
            return None, "site_id 无效"
        site = get_site(int(site_id))
        if not isinstance(site, dict):
            return None, "站点不存在"
        if int(site.get("node_id") or 0) != node_id:
            return None, "站点与节点不匹配"

        domains = payload.get("domains") if isinstance(payload.get("domains"), list) else []
        domains = [str(x).strip() for x in domains if str(x).strip()]
        if not domains:
            return None, "站点域名为空"

        site_type = str(payload.get("site_type") or "static").strip().lower()
        if site_type not in ("static", "php", "reverse_proxy"):
            site_type = "static"
        root_path = str(payload.get("root_path") or "")
        proxy_target = _normalize_proxy_target(payload.get("proxy_target") or "")
        if site_type == "reverse_proxy" and not proxy_target:
            return None, "反向代理必须填写目标地址"

        old_domains = payload.get("old_domains") if isinstance(payload.get("old_domains"), list) else []
        old_domains = [str(x).strip() for x in old_domains if str(x).strip()]
        if not old_domains:
            old_domains = list(site.get("domains") or [])
        old_root_path = str(payload.get("old_root_path") or site.get("root_path") or "")

        req_payload = {
            "name": str(payload.get("name") or site.get("name") or domains[0]).strip(),
            "domains": domains,
            "type": site_type,
            "web_server": str(site.get("web_server") or "nginx"),
            "proxy_target": proxy_target,
            "https_redirect": bool(payload.get("https_redirect")),
            "gzip_enabled": bool(payload.get("gzip_enabled")),
            "nginx_tpl": str(payload.get("nginx_tpl") or ""),
            "root_path": root_path,
            "root_base": _node_root_base(node),
            "old_domains": old_domains,
            "old_root_path": old_root_path,
            "need_php": bool(site_type == "php"),
        }
        return {
            "type": "site_update",
            "task_id": int(task_id),
            "site_id": int(site_id),
            "attempt": int(attempt),
            "request": req_payload,
        }, ""

    if t == "site_delete":
        site_id = _coerce_int(payload.get("site_id"), 0)
        if site_id <= 0:
            return None, "site_id 无效"
        site = get_site(int(site_id))
        if not isinstance(site, dict):
            return None, "站点不存在"
        if int(site.get("node_id") or 0) != node_id:
            return None, "站点与节点不匹配"
        domains = [str(x).strip() for x in (site.get("domains") or []) if str(x).strip()]
        if not domains:
            return None, "站点域名为空"
        req_payload = {
            "domains": domains,
            "root_path": str(site.get("root_path") or ""),
            "delete_root": bool(payload.get("delete_root")),
            "delete_cert": bool(payload.get("delete_cert")),
            "root_base": _node_root_base(node),
        }
        return {
            "type": "site_delete",
            "task_id": int(task_id),
            "site_id": int(site_id),
            "attempt": int(attempt),
            "request": req_payload,
        }, ""

    if t == "site_file_op":
        site_id = _coerce_int(payload.get("site_id"), 0)
        if site_id <= 0:
            return None, "site_id 无效"
        site = get_site(int(site_id))
        if not isinstance(site, dict):
            return None, "站点不存在"
        if int(site.get("node_id") or 0) != node_id:
            return None, "站点与节点不匹配"
        action = str(payload.get("action") or "").strip().lower()
        if action not in ("upload", "write", "mkdir", "delete", "unzip"):
            return None, "不支持的文件任务类型"
        req = payload.get("request") if isinstance(payload.get("request"), dict) else {}
        req_payload = dict(req or {})
        root = str(req_payload.get("root") or site.get("root_path") or "").strip()
        if not root:
            return None, "站点根目录为空"
        req_payload["root"] = root
        req_payload["root_base"] = _node_root_base(node)
        if action == "upload":
            content_b64 = str(req_payload.get("content_b64") or "")
            allow_empty = bool(req_payload.get("allow_empty"))
            if not content_b64 and not allow_empty:
                return None, "上传文件内容为空"
        return {
            "type": "site_file_op",
            "task_id": int(task_id),
            "site_id": int(site_id),
            "attempt": int(attempt),
            "action": action,
            "request": req_payload,
        }, ""

    if t in ("remote_storage_mount", "remote_storage_unmount"):
        profile_id = _remote_profile_id(payload.get("profile_id"))
        if not profile_id:
            return None, "profile_id 无效"
        req = payload.get("request") if isinstance(payload.get("request"), dict) else {}
        if not isinstance(req, dict) or not req:
            return None, "挂载请求为空"
        req_payload = dict(req)
        pwd = str(req_payload.get("password") or "").strip()
        if not pwd:
            pwd = _remote_storage_decrypt_password(req_payload.get("password_enc"))
        req_payload["password"] = pwd
        req_payload.pop("password_enc", None)
        action = _remote_mount_action_for_type(t, payload.get("action"))
        return {
            "type": t,
            "task_id": int(task_id),
            "profile_id": profile_id,
            "attempt": int(attempt),
            "action": action,
            "request": req_payload,
        }, ""

    if t == "website_env_ensure":
        include_php = bool(payload.get("include_php"))
        return {
            "type": t,
            "task_id": int(task_id),
            "attempt": int(attempt),
            "need_nginx": True,
            "need_php": bool(include_php),
            "need_acme": True,
        }, ""

    if t == "website_env_uninstall":
        purge_data = bool(payload.get("purge_data"))
        deep_uninstall = bool(payload.get("deep_uninstall"))
        sites_payload: List[Dict[str, Any]] = []
        if purge_data and node_id > 0:
            for s in list_sites(node_id=node_id):
                if not isinstance(s, dict) or _is_storage_mount_site(s):
                    continue
                sites_payload.append(
                    {
                        "domains": list(s.get("domains") or []),
                        "root_path": str(s.get("root_path") or ""),
                        "root_base": _node_root_base(node),
                    }
                )
        return {
            "type": t,
            "task_id": int(task_id),
            "attempt": int(attempt),
            "purge_data": bool(purge_data),
            "deep_uninstall": bool(deep_uninstall),
            "sites": sites_payload,
        }, ""

    if t in ("website_ssl_issue", "website_ssl_renew"):
        site_id = _coerce_int(payload.get("site_id"), 0)
        cert_id = _coerce_int(payload.get("cert_id"), 0)
        if site_id <= 0:
            return None, "site_id 无效"
        site = get_site(int(site_id))
        if not isinstance(site, dict):
            return None, "站点不存在"
        if int(site.get("node_id") or 0) != node_id:
            return None, "站点与节点不匹配"
        domains = list(site.get("domains") or [])
        if not domains:
            return None, "站点域名为空"
        req_payload = {
            "domains": domains,
            "root_path": site.get("root_path") or "",
            "root_base": _node_root_base(node),
            "update_conf": {
                "type": site.get("type") or "static",
                "root_path": site.get("root_path") or "",
                "proxy_target": _normalize_proxy_target(site.get("proxy_target") or ""),
                "https_redirect": bool(site.get("https_redirect") or False),
                "gzip_enabled": True if site.get("gzip_enabled") is None else bool(site.get("gzip_enabled")),
                "nginx_tpl": site.get("nginx_tpl") or "",
            },
        }
        return {
            "type": t,
            "task_id": int(task_id),
            "site_id": int(site_id),
            "cert_id": int(cert_id),
            "attempt": int(attempt),
            "request": req_payload,
        }, ""

    return None, "不支持的任务类型"


def _next_site_task_command(node: Dict[str, Any], api_key: str) -> Optional[Dict[str, Any]]:
    node_id = int(node.get("id") or 0)
    if node_id <= 0:
        return None
    try:
        rows = list_tasks(node_id=node_id, limit=200)
    except Exception:
        rows = []
    if not rows:
        return None

    pending: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        t = str(row.get("type") or "").strip().lower()
        if t not in _SITE_TASK_TYPES:
            continue
        st = str(row.get("status") or "").strip().lower()
        if st not in ("queued", "running"):
            continue
        pending.append(row)
    if not pending:
        return None

    pending.sort(key=lambda x: _coerce_int((x or {}).get("id"), 0))
    now_ts = float(time.time())
    latest_remote_task_id_by_profile: Dict[str, int] = {}
    for row in pending:
        if not isinstance(row, dict):
            continue
        t_row = str(row.get("type") or "").strip().lower()
        if t_row not in ("remote_storage_mount", "remote_storage_unmount"):
            continue
        payload_row = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        profile_id_row = _remote_profile_id(payload_row.get("profile_id"))
        if not profile_id_row:
            continue
        task_id_row = _coerce_int(row.get("id"), 0)
        if task_id_row <= 0:
            continue
        prev_task_id = int(latest_remote_task_id_by_profile.get(profile_id_row) or 0)
        if task_id_row > prev_task_id:
            latest_remote_task_id_by_profile[profile_id_row] = int(task_id_row)

    for task in pending:
        task_id = _coerce_int(task.get("id"), 0)
        task_type = str(task.get("type") or "").strip().lower()
        if task_id <= 0:
            continue

        if task_type in ("remote_storage_mount", "remote_storage_unmount"):
            payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
            profile_id = _remote_profile_id(payload.get("profile_id"))
            latest_task_id = int(latest_remote_task_id_by_profile.get(profile_id) or 0) if profile_id else 0
            if latest_task_id > int(task_id):
                _site_task_supersede_remote_mount(task, "已被同方案的新挂载任务替代")
                continue

        status = str(task.get("status") or "").strip().lower()
        if status == "queued" and not _site_task_retry_ready(task, now_ts):
            continue
        if status == "running":
            last_dispatched_ts = _site_task_last_dispatched_ts(task)
            running_redisp = (
                float(_NETMON_TASK_RUNNING_REDISPATCH_SEC)
                if task_type == "netmon_probe"
                else float(_SITE_TASK_RUNNING_REDISPATCH_SEC)
            )
            if last_dispatched_ts > 0 and (now_ts - last_dispatched_ts) < running_redisp:
                continue

        cur_attempt = _site_task_current_attempt(task)
        max_attempts = _site_task_max_attempts(task)
        attempt = max(1, cur_attempt + 1)
        if attempt > max_attempts:
            _site_task_final_fail(node, task, "任务重试次数超限", max_attempts)
            continue

        cmd, err = _build_website_cmd(task, node, attempt)
        if not isinstance(cmd, dict):
            _site_task_final_fail(node, task, err or "任务参数无效", attempt)
            continue

        result_payload = task.get("result") if isinstance(task.get("result"), dict) else {}
        result_payload = dict(result_payload)
        result_payload.update(
            {
                "op": task_type,
                "attempt": int(attempt),
                "max_attempts": int(max_attempts),
                "last_dispatched_ts": float(now_ts),
                "next_retry_ts": 0.0,
                "dispatched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
        update_task(
            task_id,
            status="running",
            progress=_site_task_progress_for_attempt(attempt, max_attempts),
            error="",
            result=result_payload,
        )

        if task_type in ("website_ssl_issue", "website_ssl_renew") and int(attempt) == 1:
            payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
            site_id = _coerce_int(payload.get("site_id"), 0)
            if site_id > 0:
                add_site_event(
                    int(site_id),
                    _site_event_action(task_type),
                    status="running",
                    actor="agent",
                    payload={"task_id": int(task_id), "attempt": int(attempt)},
                )

        return sign_cmd(str(api_key or ""), cmd)

    return None


# ------------------------ Agent push-report API (no login) ------------------------


@router.post("/api/agent/report")
async def api_agent_report(request: Request):
    """Agent 主动上报接口。

    认证：HTTP Header `X-API-Key: <node.api_key>`。
    载荷：至少包含 node_id 字段。

    返回：commands（例如同步规则池 / 自更新）。
    """

    # Agent may gzip-compress report payload to reduce panel ingress traffic.
    try:
        content_encoding = str(request.headers.get("content-encoding") or "").strip().lower()
        gzip_encoded = "gzip" in content_encoding
        req_limit = (
            int(_AGENT_REPORT_MAX_COMPRESSED_BYTES)
            if gzip_encoded
            else int(_AGENT_REPORT_MAX_DECOMPRESSED_BYTES)
        )
        try:
            content_len = int(request.headers.get("content-length") or "0")
        except Exception:
            content_len = 0
        if content_len > 0 and content_len > req_limit:
            return JSONResponse({"ok": False, "error": "请求体过大"}, status_code=413)

        chunks = bytearray()
        total = 0
        async for chunk in request.stream():
            if not chunk:
                continue
            total += len(chunk)
            if total > req_limit:
                return JSONResponse({"ok": False, "error": "请求体过大"}, status_code=413)
            chunks.extend(chunk)
        raw = bytes(chunks)

        if gzip_encoded:
            try:
                raw = _gunzip_limited(raw, int(_AGENT_REPORT_MAX_DECOMPRESSED_BYTES))
            except _RequestBodyTooLargeError:
                return JSONResponse({"ok": False, "error": "请求体解压后过大"}, status_code=413)
        if len(raw) > int(_AGENT_REPORT_MAX_DECOMPRESSED_BYTES):
            return JSONResponse({"ok": False, "error": "请求体解压后过大"}, status_code=413)

        parsed = json.loads((raw or b"{}").decode("utf-8"))
    except Exception:
        return JSONResponse({"ok": False, "error": "请求体解析失败"}, status_code=400)

    if not isinstance(parsed, dict):
        return JSONResponse({"ok": False, "error": "请求体必须是 JSON 对象"}, status_code=400)

    payload: Dict[str, Any] = parsed

    api_key = (request.headers.get("x-api-key") or request.headers.get("X-API-Key") or "").strip()
    node_id_raw = payload.get("node_id")
    try:
        node_id = int(node_id_raw)
    except Exception:
        return JSONResponse({"ok": False, "error": "节点 ID 无效"}, status_code=400)

    node = get_node_runtime(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not api_key or api_key != node.get("api_key"):
        return JSONResponse({"ok": False, "error": "无权限（API Key 不正确）"}, status_code=403)

    # Agent software/update meta (optional)
    agent_version = str(payload.get("agent_version") or "").strip()
    if not agent_version:
        agent_version = parse_agent_version_from_ua(
            (request.headers.get("User-Agent") or request.headers.get("user-agent") or "").strip()
        )

    agent_update = payload.get("agent_update")
    if not isinstance(agent_update, dict):
        agent_update = {}
    raw_caps = payload.get("capabilities")
    # 一些旧/异常节点可能暂时不带 capabilities；
    # 这种情况下不要把库里已知能力覆盖成 {}，避免误判为旧协议。
    agent_caps: Optional[Dict[str, Any]]
    if isinstance(raw_caps, dict):
        agent_caps = _normalize_agent_caps(raw_caps)
    else:
        agent_caps = None
    now_ts = float(time.time())
    now = _fmt_dt(now_ts)

    # report_json：尽量只保存 report 字段（更干净），但也兼容直接上报全量
    report = payload.get("report") if isinstance(payload, dict) else None
    if report is None:
        report = payload
    agent_cmd_ts_candidates = _infer_agent_cmd_ts_candidates(report, now_ts)

    ack_version = payload.get("ack_version")

    # Parse agent ack version early (used for version realignment)
    try:
        agent_ack = int(ack_version) if ack_version is not None else 0
    except Exception:
        agent_ack = 0

    traffic_ack_version = payload.get("traffic_ack_version")
    try:
        traffic_ack = int(traffic_ack_version) if traffic_ack_version is not None else None
    except Exception:
        traffic_ack = None
    auto_restart_ack_version = payload.get("auto_restart_ack_version")
    try:
        auto_restart_ack = int(auto_restart_ack_version) if auto_restart_ack_version is not None else None
    except Exception:
        auto_restart_ack = None
    time_sync_ack_version = payload.get("time_sync_ack_version")
    try:
        time_sync_ack = int(time_sync_ack_version) if time_sync_ack_version is not None else None
    except Exception:
        time_sync_ack = None

    report_for_store: Any = report
    if isinstance(report, dict) and bool(node.get("desired_pool_present")) and "pool" in report:
        # Desired pool already exists on panel; avoid rewriting large pool blob every heartbeat.
        report_for_store = dict(report)
        report_for_store.pop("pool", None)

    try:
        update_node_report(
            node_id=node_id,
            report_json=json.dumps(report_for_store, ensure_ascii=False, separators=(",", ":")),
            last_seen_at=now,
            agent_ack_version=int(ack_version) if ack_version is not None else None,
            traffic_ack_version=traffic_ack,
            auto_restart_ack_version=auto_restart_ack,
        )
    except Exception:
        # 不要让写库失败影响 agent
        pass

    # Persist rule traffic/connection history (best-effort, never block agent report)
    try:
        if isinstance(report, dict) and isinstance(report.get("stats"), dict):
            ingest_stats_snapshot(node_id=node_id, stats=report.get("stats"))
    except Exception:
        pass

    # Website/NetMon async task results from agent execution (best-effort).
    try:
        _ingest_site_task_results(node, payload.get("task_results"))
    except Exception:
        pass

    # Persist agent version/capabilities (best-effort).
    # 仅当本次 payload 明确携带 capabilities 时才覆盖库中能力字段；
    # 否则保留历史值，避免短暂缺失导致“立即降级兼容旧协议”。
    try:
        extra_updates: Dict[str, Any] = {}
        if isinstance(agent_caps, dict):
            extra_updates["agent_capabilities_json"] = json.dumps(agent_caps, ensure_ascii=False)
        update_agent_status(
            node_id=node_id,
            agent_reported_version=agent_version or None,
            extra_updates=extra_updates if extra_updates else None,
            touch_update_at=False,
        )
    except Exception:
        pass

    # Persist update lifecycle status.
    # v2 agents: require update_id + command_id match.
    # legacy agents: fallback to update_id match only.
    try:
        desired_update_id_now = str(node.get("desired_agent_update_id") or "").strip()
        desired_cmd_id_now = str(node.get("desired_agent_command_id") or "").strip()
        rep_update_id = str(agent_update.get("update_id") or "").strip() if isinstance(agent_update, dict) else ""
        rep_cmd_id = str(agent_update.get("command_id") or "").strip() if isinstance(agent_update, dict) else ""
        rep_state = _canon_agent_update_state(agent_update.get("state")) if isinstance(agent_update, dict) else ""
        rep_reason = (
            str(agent_update.get("reason_code") or "").strip().lower() if isinstance(agent_update, dict) else ""
        )
        rep_msg = (
            str(agent_update.get("error") or agent_update.get("msg") or "").strip()
            if isinstance(agent_update, dict)
            else ""
        )
        rep_accepted_at = _valid_dt_str(agent_update.get("accepted_at"), now) if isinstance(agent_update, dict) else now
        rep_started_at = _valid_dt_str(agent_update.get("started_at"), now) if isinstance(agent_update, dict) else now
        rep_finished_at = _valid_dt_str(agent_update.get("finished_at"), now) if isinstance(agent_update, dict) else now
        # Use *current report* capabilities for lifecycle matching.
        # Missing capabilities should be treated as legacy/unknown (conservative),
        # instead of inheriting possibly stale v2 flags from database.
        caps_now = agent_caps if isinstance(agent_caps, dict) else node.get("agent_capabilities")
        if not isinstance(caps_now, dict):
            caps_now = {}
        supports_v2_now = _supports_update_v2(caps_now)

        if desired_update_id_now:
            same_update = bool(rep_update_id and rep_update_id == desired_update_id_now)
            matched = bool(same_update)
            if matched and supports_v2_now and desired_cmd_id_now and rep_cmd_id and (rep_cmd_id != desired_cmd_id_now):
                # Out-of-order or legacy-compat execution may report a previous command_id.
                # For progressed states, prefer update_id continuity to avoid delivered-stall.
                matched = rep_state in ("accepted", "running", "done", "failed")

            if matched:
                if rep_state == "delivered":
                    update_agent_status(
                        node_id=node_id,
                        state="delivered",
                        msg=(rep_msg or "节点已收到更新命令"),
                        reason_code="",
                        extra_updates={
                            "agent_update_next_retry_at": None,
                        },
                        touch_update_at=True,
                    )
                elif rep_state == "queued":
                    update_agent_status(
                        node_id=node_id,
                        state="queued",
                        msg=(rep_msg or "更新任务排队中"),
                        reason_code="",
                        extra_updates={
                            "agent_update_next_retry_at": None,
                        },
                        touch_update_at=True,
                    )
                if rep_state == "accepted":
                    update_agent_status(
                        node_id=node_id,
                        state="accepted",
                        msg=(rep_msg or "节点已确认更新命令"),
                        reason_code="",
                        extra_updates={
                            "agent_update_accepted_at": rep_accepted_at,
                            "agent_update_started_at": None,
                            "agent_update_finished_at": None,
                            "agent_update_next_retry_at": None,
                        },
                        touch_update_at=True,
                    )
                elif rep_state == "running":
                    update_agent_status(
                        node_id=node_id,
                        state="running",
                        msg=(rep_msg or "节点正在执行安装"),
                        reason_code="",
                        extra_updates={
                            "agent_update_accepted_at": rep_accepted_at,
                            "agent_update_started_at": rep_started_at,
                            "agent_update_finished_at": None,
                            "agent_update_next_retry_at": None,
                        },
                        touch_update_at=True,
                    )
                elif rep_state == "done":
                    update_agent_status(
                        node_id=node_id,
                        state="done",
                        msg=(rep_msg or ""),
                        reason_code="",
                        extra_updates={
                            "agent_update_finished_at": rep_finished_at,
                            "agent_update_next_retry_at": None,
                        },
                        touch_update_at=True,
                    )
                elif rep_state == "failed":
                    reason = _infer_agent_fail_reason(rep_reason, rep_msg)
                    try:
                        retry_count_now = int(node.get("agent_update_retry_count") or 0)
                    except Exception:
                        retry_count_now = 0
                    try:
                        max_retries_now = int(node.get("agent_update_max_retries") or 0)
                    except Exception:
                        max_retries_now = 0
                    if max_retries_now <= 0:
                        max_retries_now = int(_AGENT_UPDATE_MAX_RETRIES)
                    retry_count_now = max(0, int(retry_count_now))
                    retryable = not _is_terminal_fail_reason(reason)

                    if retryable and retry_count_now < max_retries_now:
                        wait_s = _agent_retry_backoff_sec(retry_count_now + 1)
                        next_retry_at = _fmt_dt(now_ts + wait_s)
                        update_agent_status(
                            node_id=node_id,
                            state="retrying",
                            msg=(
                                rep_msg
                                or _reason_text(reason)
                                or f"节点执行失败，已安排重试（{retry_count_now}/{max_retries_now}）"
                            ),
                            reason_code=reason,
                            extra_updates={
                                "agent_update_next_retry_at": next_retry_at,
                                "agent_update_finished_at": None,
                            },
                            touch_update_at=True,
                        )
                    else:
                        final_reason = reason
                        if retryable and retry_count_now >= max_retries_now:
                            final_reason = "retry_exhausted"
                        update_agent_status(
                            node_id=node_id,
                            state="failed",
                            msg=(rep_msg or _reason_text(final_reason) or "节点执行更新失败"),
                            reason_code=final_reason,
                            extra_updates={
                                "agent_update_finished_at": rep_finished_at,
                                "agent_update_next_retry_at": None,
                            },
                            touch_update_at=True,
                        )
        else:
            if rep_state:
                update_agent_status(
                    node_id=node_id,
                    state=rep_state,
                    msg=(rep_msg or None),
                    reason_code=(rep_reason or None),
                    touch_update_at=True,
                )
    except Exception:
        pass

    # Refresh node snapshot after potential status updates.
    try:
        node = get_node_runtime(node_id) or node
    except Exception:
        pass

    # 若面板尚无 desired_pool，则尝试把 agent 当前 pool 作为初始 desired_pool。
    # ⚠️ 关键：当面板重装/恢复后，Agent 可能还保留旧的 ack_version（例如 33），
    # 如果面板把 desired_pool_version 从 1 开始，后续新增规则会一直小于 ack_version，
    # 导致面板永远不下发 commands，看起来像“不同步”。
    # 这里将面板 desired_pool_version 对齐到 agent_ack（至少 1），避免版本回退。
    desired_ver, desired_pool = get_desired_pool(node_id)
    if desired_pool is None:
        rep_pool = None
        if isinstance(report, dict):
            rep_pool = report.get("pool")
        if isinstance(rep_pool, dict):
            init_ver = max(1, agent_ack)
            desired_ver, desired_pool = set_desired_pool_exact(node_id, rep_pool, init_ver)
    else:
        # Desired exists but version is behind agent ack (panel DB reset or migrated)
        if agent_ack > desired_ver:
            rep_pool = None
            if isinstance(report, dict):
                rep_pool = report.get("pool")
            if isinstance(rep_pool, dict):
                # Trust agent as source of truth when panel version went backwards (e.g. DB restore).
                desired_ver, desired_pool = set_desired_pool_exact(node_id, rep_pool, agent_ack)
            else:
                desired_ver = set_desired_pool_version_exact(node_id, agent_ack)

    # 自适应负载均衡：基于实时探测结果自动调权（单次仅调整一条规则，优先走 pool_patch）
    try:
        if isinstance(desired_pool, dict) and isinstance(report, dict):
            adaptive = suggest_adaptive_pool_patch(
                node_id=int(node_id),
                desired_ver=int(desired_ver),
                agent_ack=int(agent_ack),
                desired_pool=desired_pool,
                report=report,
            )
            if isinstance(adaptive, dict) and isinstance(adaptive.get("pool"), dict):
                desired_ver, desired_pool = set_desired_pool(node_id, adaptive["pool"])
    except Exception:
        # Never break agent heartbeat because of auto-LB logic.
        pass

    def _sign_for_node(cmd_obj: Dict[str, Any], ts_override: Optional[int] = None) -> Dict[str, Any]:
        out_cmd = dict(cmd_obj or {})
        ts_i = int(ts_override) if ts_override is not None else int(now_ts or 0)
        if ts_i > 0:
            out_cmd["ts"] = ts_i
        return sign_cmd(str(node.get("api_key") or ""), out_cmd)

    # 下发命令：规则池同步
    cmds: List[Dict[str, Any]] = []
    if isinstance(desired_pool, dict) and desired_ver > agent_ack:
        # ✅ 单条规则增量下发：仅当 agent 落后 1 个版本，且报告中存在当前 pool 时才尝试 patch
        base_pool = None
        if isinstance(report, dict):
            base_pool = report.get("pool") if isinstance(report.get("pool"), dict) else None

        cmd: Dict[str, Any]
        ops = None
        if desired_ver == agent_ack + 1 and isinstance(base_pool, dict):
            ops = single_rule_ops(base_pool, desired_pool)

        if isinstance(ops, list) and len(ops) == 1:
            cmd = {
                "type": "pool_patch",
                "version": desired_ver,
                "base_version": agent_ack,
                "ops": ops,
                "apply": True,
            }
        else:
            cmd = {
                "type": "sync_pool",
                "version": desired_ver,
                "pool": desired_pool,
                "apply": True,
            }

        cmds.append(_sign_for_node(cmd))

    # 下发命令：Agent 自更新（可选）
    try:
        desired_agent_ver = str(node.get("desired_agent_version") or "").strip()
        desired_update_id = str(node.get("desired_agent_update_id") or "").strip()
        if desired_agent_ver and desired_update_id:
            rollout_state = _canon_agent_update_state(node.get("agent_update_state") or "queued")
            cmd_id = str(node.get("desired_agent_command_id") or "").strip()
            reason_code_now = str(node.get("agent_update_reason_code") or "").strip().lower()

            try:
                retry_count = int(node.get("agent_update_retry_count") or 0)
            except Exception:
                retry_count = 0
            try:
                max_retries = int(node.get("agent_update_max_retries") or 0)
            except Exception:
                max_retries = 0
            if max_retries <= 0:
                max_retries = int(_AGENT_UPDATE_MAX_RETRIES)
            retry_count = max(0, int(retry_count))

            delivered_ts = _parse_dt(node.get("agent_update_delivered_at"))
            accepted_ts = _parse_dt(node.get("agent_update_accepted_at"))
            started_ts = _parse_dt(node.get("agent_update_started_at"))
            next_retry_ts = _parse_dt(node.get("agent_update_next_retry_at"))

            caps = node.get("agent_capabilities")
            if not isinstance(caps, dict):
                caps = {}
            supports_v2 = _supports_update_v2(caps)

            if rollout_state not in ("done", "failed", "expired"):
                # Legacy agents do not report "accepted". keep state machine compatible.
                if rollout_state == "accepted" and not supports_v2:
                    rollout_state = "delivered"

                # 1) Timeout -> retrying / expired
                if rollout_state == "delivered":
                    ack_required = bool(supports_v2 and cmd_id)
                    delivered_timeout = float(
                        _AGENT_UPDATE_ACK_TIMEOUT_SEC if ack_required else _AGENT_UPDATE_LEGACY_DELIVERED_TIMEOUT_SEC
                    )
                    deadline_ts = next_retry_ts if next_retry_ts > 0 else (
                        delivered_ts + delivered_timeout if delivered_ts > 0 else 0.0
                    )
                    if deadline_ts > 0 and now_ts >= deadline_ts:
                        if retry_count >= max_retries:
                            reason = "ack_timeout_exhausted" if ack_required else "running_timeout_exhausted"
                            update_agent_status(
                                node_id=node_id,
                                state="expired",
                                msg=_reason_text(reason) or "等待节点状态确认超时，已结束本次更新批次。",
                                reason_code=reason,
                                extra_updates={
                                    "agent_update_next_retry_at": None,
                                    "agent_update_finished_at": now,
                                },
                                touch_update_at=True,
                            )
                            rollout_state = "expired"
                        else:
                            wait_s = _agent_retry_backoff_sec(retry_count + 1)
                            next_retry_at = _fmt_dt(now_ts + wait_s)
                            reason = "ack_timeout" if ack_required else "running_timeout"
                            update_agent_status(
                                node_id=node_id,
                                state="retrying",
                                msg=_reason_text(reason) or "等待节点状态确认超时，已安排重试。",
                                reason_code=reason,
                                extra_updates={"agent_update_next_retry_at": next_retry_at},
                                touch_update_at=True,
                            )
                            rollout_state = "retrying"
                            next_retry_ts = _parse_dt(next_retry_at)
                elif rollout_state in ("accepted", "running"):
                    running_from = started_ts if started_ts > 0 else (accepted_ts if accepted_ts > 0 else delivered_ts)
                    if running_from > 0 and now_ts >= (running_from + float(_AGENT_UPDATE_RUNNING_TIMEOUT_SEC)):
                        if retry_count >= max_retries:
                            reason = "running_timeout_exhausted"
                            update_agent_status(
                                node_id=node_id,
                                state="expired",
                                msg=_reason_text(reason) or "节点执行更新超时，已结束本次更新批次。",
                                reason_code=reason,
                                extra_updates={
                                    "agent_update_next_retry_at": None,
                                    "agent_update_finished_at": now,
                                },
                                touch_update_at=True,
                            )
                            rollout_state = "expired"
                        else:
                            wait_s = _agent_retry_backoff_sec(retry_count + 1)
                            next_retry_at = _fmt_dt(now_ts + wait_s)
                            reason = "running_timeout"
                            update_agent_status(
                                node_id=node_id,
                                state="retrying",
                                msg=_reason_text(reason) or "节点执行更新超时，已安排重试。",
                                reason_code=reason,
                                extra_updates={"agent_update_next_retry_at": next_retry_at},
                                touch_update_at=True,
                            )
                            rollout_state = "retrying"
                            next_retry_ts = _parse_dt(next_retry_at)

                # 2) Dispatch command when queued/retrying/delivered.
                # Split to:
                #   - new: start a new attempt (increments retry_count).
                #   - redeliver: same attempt periodic resend (no retry_count jump).
                early_compat = bool(
                    rollout_state == "delivered"
                    and supports_v2
                    and bool(cmd_id)
                    and accepted_ts <= 0
                    and started_ts <= 0
                    and delivered_ts > 0
                    and now_ts >= (delivered_ts + float(_AGENT_UPDATE_EARLY_COMPAT_SEC))
                )
                redeliver_due = bool(
                    rollout_state == "delivered"
                    and accepted_ts <= 0
                    and started_ts <= 0
                    and delivered_ts > 0
                    and now_ts >= (delivered_ts + float(_AGENT_UPDATE_REDISPATCH_SEC))
                )
                should_dispatch = False
                dispatch_kind = ""
                if rollout_state == "queued":
                    should_dispatch = True
                    dispatch_kind = "new"
                elif rollout_state == "retrying":
                    if next_retry_ts <= 0 or now_ts >= next_retry_ts:
                        should_dispatch = True
                        dispatch_kind = "new"
                elif rollout_state == "delivered" and supports_v2 and not cmd_id:
                    # migrated rows may have delivered state but no command id.
                    should_dispatch = True
                    dispatch_kind = "new"
                elif rollout_state == "delivered" and (not supports_v2) and cmd_id:
                    # node no longer reports v2 capabilities, but row still carries
                    # historical command_id: keep same attempt and compat-resend.
                    should_dispatch = True
                    dispatch_kind = "redeliver"
                elif early_compat:
                    # v2 node keeps heartbeat but does not send accepted/running.
                    should_dispatch = True
                    dispatch_kind = "redeliver"
                elif redeliver_due:
                    # periodic resend to survive transient response loss/timeouts.
                    should_dispatch = True
                    dispatch_kind = "redeliver"

                if should_dispatch:
                    is_new_attempt = bool(dispatch_kind == "new")
                    attempt_no = max(1, (retry_count + 1) if is_new_attempt else (retry_count if retry_count > 0 else 1))

                    panel_base = panel_public_base_url(request)
                    report_base = str(request.base_url).rstrip("/")
                    sh_url, zip_url, github_only = agent_asset_urls(panel_base)
                    fallback_sh_url, fallback_zip_url = agent_fallback_asset_urls(panel_base)
                    # 自更新下载采用“双地址候选”：
                    # - 主：面板公开地址（兼容大多数节点）
                    # - 备：该节点本次上报实际入口（常见为 IP:6080）
                    # 这样避免全局切换导致“修了一批、坏了一批”。
                    if report_base and report_base != panel_base:
                        fallback_sh_url = f"{report_base}/static/realm_agent.sh"
                        fallback_zip_url = f"{report_base}/static/realm-agent.zip"
                    panel_zip_sha256 = file_sha256(STATIC_DIR / "realm-agent.zip")
                    zip_sha256 = "" if github_only else panel_zip_sha256
                    fallback_zip_sha256 = ""
                    try:
                        fallback_zip_url_s = str(fallback_zip_url or "").strip()
                        panel_zip_url = f"{panel_base}/static/realm-agent.zip"
                        if (
                            fallback_zip_url_s.endswith("/static/realm-agent.zip")
                            and (fallback_zip_url_s.startswith("http://") or fallback_zip_url_s.startswith("https://"))
                            and panel_zip_sha256
                        ):
                            fallback_zip_sha256 = panel_zip_sha256
                        if str(fallback_zip_url or "").strip() == panel_zip_url and panel_zip_sha256:
                            fallback_zip_sha256 = panel_zip_sha256
                    except Exception:
                        fallback_zip_sha256 = ""

                    base_ucmd: Dict[str, Any] = {
                        "type": "update_agent",
                        "update_id": desired_update_id,
                        "desired_version": desired_agent_ver,
                        "panel_url": panel_base,
                        "panel_ip_fallback_port": (
                            _explicit_url_port(report_base)
                            or _explicit_url_port(panel_base)
                            or setting_int(
                                "agent_panel_ip_fallback_port",
                                default=6080,
                                lo=1,
                                hi=65535,
                                env_names=["REALM_PANEL_IP_FALLBACK_PORT"],
                            )
                        ),
                        "sh_url": sh_url,
                        "zip_url": zip_url,
                        "zip_sha256": zip_sha256,
                        "fallback_sh_url": fallback_sh_url,
                        "fallback_zip_url": fallback_zip_url,
                        "fallback_zip_sha256": fallback_zip_sha256,
                        "github_only": bool(github_only),
                        "force": True,
                    }

                    force_compat = bool(
                        (not supports_v2)
                        or early_compat
                        or (supports_v2 and retry_count >= 1 and reason_code_now in ("ack_timeout",))
                    )
                    use_v2_dispatch = bool(supports_v2 and (not force_compat))
                    command_id = ""
                    dispatch_variants: List[Dict[str, Any]] = []
                    if use_v2_dispatch:
                        if (not is_new_attempt) and cmd_id:
                            command_id = str(cmd_id)
                        else:
                            command_id = uuid.uuid4().hex
                        v2_cmd = dict(base_ucmd)
                        v2_cmd["command_id"] = command_id
                        v2_cmd["update_protocol_version"] = 2
                        dispatch_variants.append(v2_cmd)
                        if dispatch_kind == "redeliver":
                            # Shadow legacy command helps old/hybrid agents converge.
                            dispatch_variants.append(dict(base_ucmd))
                    else:
                        dispatch_variants.append(dict(base_ucmd))

                    if use_v2_dispatch:
                        if dispatch_kind == "redeliver":
                            dispatch_msg = f"命令重投（尝试 {attempt_no}/{max_retries}），等待节点确认"
                        else:
                            dispatch_msg = f"命令已投递（尝试 {attempt_no}/{max_retries}），等待节点确认"
                    else:
                        if supports_v2:
                            if dispatch_kind == "redeliver":
                                dispatch_msg = f"命令重投（兼容模式降级，尝试 {attempt_no}/{max_retries}）"
                            else:
                                dispatch_msg = f"命令已投递（兼容模式降级，尝试 {attempt_no}/{max_retries}）"
                        else:
                            if dispatch_kind == "redeliver":
                                dispatch_msg = f"命令重投（兼容旧版协议，尝试 {attempt_no}/{max_retries}）"
                            else:
                                dispatch_msg = f"命令已投递（兼容旧版协议，尝试 {attempt_no}/{max_retries}）"

                    if reason_code_now == "signature_rejected":
                        ts_candidates = [int(now_ts)]
                        for tsv in list(agent_cmd_ts_candidates or []):
                            try:
                                ts_i = int(tsv)
                            except Exception:
                                continue
                            if ts_i not in ts_candidates:
                                ts_candidates.append(ts_i)
                        # full timezone sweep (<=57 variants) to pass legacy skew checks
                        for tsv in ts_candidates[:57]:
                            for out_cmd in dispatch_variants:
                                cmds.append(_sign_for_node(out_cmd, ts_override=int(tsv)))
                    else:
                        for out_cmd in dispatch_variants:
                            cmds.append(_sign_for_node(out_cmd))

                    timeout_window = float(
                        _AGENT_UPDATE_ACK_TIMEOUT_SEC
                        if use_v2_dispatch
                        else _AGENT_UPDATE_LEGACY_DELIVERED_TIMEOUT_SEC
                    )
                    extra_updates: Dict[str, Any] = {
                        "desired_agent_command_id": (command_id if use_v2_dispatch else ""),
                        "agent_update_retry_count": int(attempt_no),
                        "agent_update_max_retries": int(max_retries),
                        "agent_update_delivered_at": now,
                    }
                    if is_new_attempt:
                        extra_updates["agent_update_next_retry_at"] = _fmt_dt(now_ts + timeout_window)
                        extra_updates["agent_update_accepted_at"] = None
                        extra_updates["agent_update_started_at"] = None
                        extra_updates["agent_update_finished_at"] = None
                    elif next_retry_ts <= 0 or (
                        (not use_v2_dispatch) and next_retry_ts > (now_ts + timeout_window + 1.0)
                    ):
                        # 历史兼容：老记录可能带着过长 deadline（如 2h）。
                        # 对旧协议分支收敛到当前超时窗口，避免界面长期“卡住”。
                        extra_updates["agent_update_next_retry_at"] = _fmt_dt(now_ts + timeout_window)

                    update_agent_status(
                        node_id=node_id,
                        state="delivered",
                        msg=dispatch_msg,
                        reason_code="",
                        extra_updates=extra_updates,
                        touch_update_at=True,
                    )

    except Exception:
        pass


    # 下发命令：一键重置规则流量（可选）
    try:
        desired_reset_ver = int(node.get("desired_traffic_reset_version") or 0)
    except Exception:
        desired_reset_ver = 0

    try:
        ack_reset_ver = int(traffic_ack) if traffic_ack is not None else int(node.get("agent_traffic_reset_ack_version") or 0)
    except Exception:
        ack_reset_ver = 0

    try:
        if desired_reset_ver > 0 and desired_reset_ver > ack_reset_ver:
            rcmd = {
                "type": "reset_traffic",
                "version": desired_reset_ver,
                "reset_iptables": True,
                "reset_baseline": True,
                "reset_ss_cache": True,
                "reset_conn_history": True,
            }
            cmds.append(_sign_for_node(rcmd))
    except Exception:
        pass

    # 下发命令：节点自动重启策略（可选）
    try:
        desired_restart_ver = int(node.get("desired_auto_restart_policy_version") or 0)
    except Exception:
        desired_restart_ver = 0
    try:
        ack_restart_ver = (
            int(auto_restart_ack) if auto_restart_ack is not None else int(node.get("agent_auto_restart_policy_ack_version") or 0)
        )
    except Exception:
        ack_restart_ver = 0

    try:
        if desired_restart_ver > 0 and desired_restart_ver > ack_restart_ver:
            pol = node_auto_restart_policy_from_row(node if isinstance(node, dict) else {})
            interval_v = _coerce_int(pol.get("interval"), 1)
            if interval_v < 1:
                interval_v = 1
            if interval_v > 365:
                interval_v = 365
            hour_v = _coerce_int(pol.get("hour"), 4)
            if hour_v < 0:
                hour_v = 0
            if hour_v > 23:
                hour_v = 23
            minute_v = _coerce_int(pol.get("minute"), 8)
            if minute_v < 0:
                minute_v = 0
            if minute_v > 59:
                minute_v = 59
            weekdays_raw = pol.get("weekdays")
            weekdays_v = list(weekdays_raw) if isinstance(weekdays_raw, list) else [1, 2, 3, 4, 5, 6, 7]
            monthdays_raw = pol.get("monthdays")
            monthdays_v = list(monthdays_raw) if isinstance(monthdays_raw, list) else [1]
            pcmd = {
                "type": "auto_restart_policy",
                "version": int(desired_restart_ver),
                "policy": {
                    "enabled": bool(pol.get("enabled", True)),
                    "schedule_type": str(pol.get("schedule_type") or "daily"),
                    "interval": int(interval_v),
                    "hour": int(hour_v),
                    "minute": int(minute_v),
                    "weekdays": weekdays_v,
                    "monthdays": monthdays_v,
                },
            }
            cmds.append(_sign_for_node(pcmd))
    except Exception:
        pass

    # 下发命令：网站任务 + NetMon 私网探测任务（均由 agent push-report 队列执行）
    try:
        site_cmd = _next_site_task_command(node, str(node.get("api_key") or ""))
        if isinstance(site_cmd, dict):
            cmds.append(site_cmd)
    except Exception:
        pass

    # 下发命令：系统时间同步（可选，面板设置驱动）
    # 必须放在 commands 尾部：若执行了立即校时，避免影响后续命令验签时间窗。
    try:
        time_sync_enabled = bool(setting_bool("agent_time_sync_enabled", default=False))
        if time_sync_enabled:
            desired_time_sync_ver = int(setting_int("agent_time_sync_version", default=1, lo=1, hi=2147483647))
            ack_time_sync_ver = int(time_sync_ack) if time_sync_ack is not None else 0
            if desired_time_sync_ver > ack_time_sync_ver:
                tcmd = {
                    "type": "time_sync",
                    "version": int(desired_time_sync_ver),
                    "timezone": _normalize_tz_name(
                        setting_str("agent_time_sync_timezone", default="Asia/Shanghai"),
                        default="Asia/Shanghai",
                    ),
                    "set_timezone": bool(setting_bool("agent_time_sync_set_timezone", default=True)),
                    "enable_ntp": bool(setting_bool("agent_time_sync_enable_ntp", default=True)),
                    "set_clock": bool(setting_bool("agent_time_sync_set_clock", default=False)),
                    "panel_ts": int(now_ts),
                }
                cmds.append(_sign_for_node(tcmd))
    except Exception:
        pass

    return {
        "ok": True,
        "server_time": now,
        "server_ts": int(now_ts),
        "desired_version": desired_ver,
        "commands": cmds,
    }


# ------------------------ API (needs login) ------------------------


@router.get("/api/agents/latest")
async def api_agents_latest(_: Request, user: str = Depends(require_login)):
    """Return the latest agent version bundled with this panel."""
    latest = read_latest_agent_version()
    zip_sha256 = file_sha256(STATIC_DIR / "realm-agent.zip")
    return {
        "ok": True,
        "latest_version": latest,
        "zip_sha256": zip_sha256,
    }


@router.post("/api/agents/update_all")
async def api_agents_update_all(request: Request, user: str = Depends(require_login)):
    """Trigger an agent rollout to all nodes."""
    target = (read_latest_agent_version() or "").strip()
    if not target:
        return JSONResponse(
            {
                "ok": False,
                "error": "无法确定当前面板内置的 Agent 版本（realm-agent.zip 缺失或不可解析）",
            },
            status_code=500,
        )

    update_id = uuid.uuid4().hex
    affected = 0
    try:
        affected = set_agent_rollout_all(
            desired_version=target,
            update_id=update_id,
            state="queued",
            msg="",
            max_retries=int(_AGENT_UPDATE_MAX_RETRIES),
        )
    except Exception:
        affected = 0

    return {
        "ok": True,
        "update_id": update_id,
        "target_version": target,
        "max_retries": int(_AGENT_UPDATE_MAX_RETRIES),
        "affected": affected,
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.get("/api/agents/update_progress")
async def api_agents_update_progress(update_id: str = "", user: str = Depends(require_login)):
    """Return rollout progress."""
    uid = (update_id or "").strip()
    nodes = list_nodes()
    orders = get_group_orders()
    now_ts = float(time.time())
    now_str = _fmt_dt(now_ts)

    items: List[Dict[str, Any]] = []
    summary = {
        "total": 0,
        "done": 0,
        "failed": 0,
        "expired": 0,
        "running": 0,
        "accepted": 0,
        "delivered": 0,
        "retrying": 0,
        "queued": 0,
        "offline": 0,
        "other": 0,
    }
    active_states = {"queued", "delivered", "accepted", "running", "retrying"}

    for n in nodes:
        nuid = str(n.get("desired_agent_update_id") or "").strip()
        if uid and nuid != uid:
            continue

        summary["total"] += 1
        online = is_report_fresh(n)
        if not online:
            summary["offline"] += 1

        desired = str(n.get("desired_agent_version") or "").strip()
        cur = str(n.get("agent_reported_version") or "").strip()
        st = _canon_agent_update_state(n.get("agent_update_state") or "queued")
        reason = str(n.get("agent_update_reason_code") or "").strip().lower()
        msg = str(n.get("agent_update_msg") or "").strip()

        # Offline sweep: avoid infinite "delivered/running" when node disappeared.
        if (not online) and st in active_states:
            ref_ts = _parse_dt(n.get("agent_update_delivered_at")) or _parse_dt(n.get("agent_update_at"))
            if ref_ts > 0 and (now_ts - ref_ts) >= float(_AGENT_UPDATE_OFFLINE_EXPIRE_SEC):
                st = "expired"
                reason = "offline_timeout"
                msg = _reason_text(reason) or "节点长期离线，更新任务已过期。"
                try:
                    update_agent_status(
                        node_id=int(n.get("id") or 0),
                        state="expired",
                        msg=msg,
                        reason_code=reason,
                        extra_updates={
                            "agent_update_next_retry_at": None,
                            "agent_update_finished_at": now_str,
                        },
                        touch_update_at=True,
                    )
                except Exception:
                    pass

        if not msg and reason:
            msg = _reason_text(reason) or ""

        if st in summary:
            summary[st] += 1
        else:
            summary["other"] += 1

        group_name = str(n.get("group_name") or "").strip() or "默认分组"
        group_order = int(orders.get(group_name, 9999) or 9999)
        try:
            retry_count_val = int(n.get("agent_update_retry_count") or 0)
        except Exception:
            retry_count_val = 0
        try:
            max_retries_val = int(n.get("agent_update_max_retries") or 0)
        except Exception:
            max_retries_val = 0

        items.append(
            {
                "id": n.get("id"),
                "name": n.get("name"),
                "group_name": group_name,
                "group_order": group_order,
                "online": bool(online),
                "agent_version": cur,
                "desired_version": desired,
                "state": st,
                "msg": msg,
                "reason_code": reason,
                "command_id": str(n.get("desired_agent_command_id") or "").strip(),
                "retry_count": int(retry_count_val),
                "max_retries": int(max_retries_val),
                "next_retry_at": n.get("agent_update_next_retry_at"),
                "last_seen_at": n.get("last_seen_at"),
            }
        )

    # Backward-compatible summary aliases for old UI readers.
    summary["installing"] = int(summary.get("running") or 0)
    summary["sent"] = int(summary.get("delivered") or 0)

    # Deterministic ordering (group order -> group -> name -> id)
    try:
        items.sort(
            key=lambda x: (
                int(x.get("group_order") or 9999),
                str(x.get("group_name") or ""),
                str(x.get("name") or ""),
                int(x.get("id") or 0),
            )
        )
    except Exception:
        pass

    return {"ok": True, "update_id": uid, "summary": summary, "nodes": items}


@router.post("/api/panel/update/start")
async def api_panel_update_start(_: Request, user: str = Depends(require_login)):
    global _PANEL_UPDATE_WORKER
    global _PANEL_UPDATE_WORKER_JOB_ID
    _ = user
    _panel_update_prune_memory()
    current = _panel_update_reconcile(_panel_update_snapshot(""))
    if isinstance(current, dict):
        st = _panel_update_canon_status(current.get("status"))
        if st in _PANEL_UPDATE_ACTIVE_STATES:
            return {"ok": True, "reused": True, **_panel_update_public(current)}

    job_id = uuid.uuid4().hex
    _panel_update_touch(
        job_id,
        status="running",
        progress=1,
        stage="准备更新任务",
        message="",
        append_log="任务已创建，等待执行",
    )

    try:
        t = threading.Thread(
            target=_panel_update_run_worker,
            args=(job_id,),
            name=f"panel-update-{job_id[:8]}",
            daemon=True,
        )
        with _PANEL_UPDATE_LOCK:
            _PANEL_UPDATE_WORKER = t
            _PANEL_UPDATE_WORKER_JOB_ID = str(job_id)
        t.start()
    except Exception as exc:
        snap = _panel_update_touch(
            job_id,
            status="failed",
            progress=100,
            stage="更新失败",
            message=f"更新任务启动失败：{exc}",
            append_log=f"更新任务启动失败：{exc}",
        )
        return JSONResponse({"ok": False, "error": snap.get("message") or "更新任务启动失败"}, status_code=500)

    snap = _panel_update_snapshot(job_id)
    return {"ok": True, "reused": False, **_panel_update_public(_panel_update_reconcile(snap))}


@router.get("/api/panel/update/progress")
async def api_panel_update_progress(job_id: str = "", user: str = Depends(require_login)):
    _ = user
    _panel_update_prune_memory()
    jid = str(job_id or "").strip()
    snap = _panel_update_snapshot(jid)
    if not isinstance(snap, dict):
        if jid:
            return JSONResponse({"ok": False, "error": "更新任务不存在或已过期"}, status_code=404)
        return {"ok": True, **_panel_update_public(None)}
    snap = _panel_update_reconcile(snap)
    return {"ok": True, **_panel_update_public(snap)}
