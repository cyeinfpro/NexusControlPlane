# Nexus Network Control Plane（完整使用手册）

Nexus 是一个面向多节点网络转发与网站运维的一体化控制平面，包含两个核心组件：

- `Panel`：集中编排、可视化管理、监控、备份、权限控制
- `Agent`：节点执行器，负责规则落地、状态上报、网站操作与文件管理

本仓库当前代码版本（以源码为准）：

- `Panel v34`（`/Users/liangchanghua/Downloads/nexus/panel/app/core/settings.py`）
- `Agent v43`（`/Users/liangchanghua/Downloads/nexus/agent/app/main.py`）

---

## 目录

- [1. 适用场景与目标](#1-适用场景与目标)
- [2. 架构与工作原理](#2-架构与工作原理)
- [3. 10 分钟快速开始](#3-10-分钟快速开始)
- [4. 核心概念（必须先理解）](#4-核心概念必须先理解)
- [5. 功能总览（按模块）](#5-功能总览按模块)
- [6. 规则系统详细说明（普通转发 / WSS / 内网穿透）](#6-规则系统详细说明普通转发--wss--内网穿透)
- [7. 网站管理详细说明](#7-网站管理详细说明)
- [8. 文件管理与分享详细说明](#8-文件管理与分享详细说明)
- [9. 备份与恢复详细说明](#9-备份与恢复详细说明)
- [10. 权限、账号与审计](#10-权限账号与审计)
- [11. Agent 生命周期管理（升级/自动重启/时间同步）](#11-agent-生命周期管理升级自动重启时间同步)
- [12. 安装部署（生产建议）](#12-安装部署生产建议)
- [13. API 实战示例](#13-api-实战示例)
- [14. 常用配置项（环境变量）](#14-常用配置项环境变量)
- [15. 关键目录与文件](#15-关键目录与文件)
- [16. 常用运维命令](#16-常用运维命令)
- [17. 故障排查手册](#17-故障排查手册)
- [18. 本地开发运行](#18-本地开发运行)
- [19. 安全建议](#19-安全建议)
- [20. 免责声明](#20-免责声明)

---

## 1. 适用场景与目标

### 1.1 你会在什么场景用到 Nexus

- 你有多台节点，需要统一管理端口转发规则
- 你需要把“公网入口 A + 内网出口 B”的隧道能力可视化并可控
- 你需要在弱网络、NAT、私网节点场景中稳定下发配置
- 你希望把站点创建、SSL、文件管理、分享统一到同一个控制台
- 你希望有审计记录、角色权限、备份恢复、历史曲线

### 1.2 Nexus 解决的核心问题

- 规则分散、变更不可追踪
- 面板直连 Agent 不稳定导致管理动作失败
- WSS/内网穿透双端规则容易手工错配
- 网站运维与转发运维割裂（工具链碎片化）

---

## 2. 架构与工作原理

### 2.1 总体架构

```text
Browser
  -> Panel (FastAPI + SQLite)
       - 保存 desired 配置（规则池、站点、监控、策略）
       - 接收 Agent 上报 report/stats/sys
       - 下发签名命令（sync_pool / pool_patch / update / traffic_reset / time_sync）

Agent (FastAPI)
  - 周期上报到 Panel（push-report）
  - 执行命令并 ACK 版本
  - 把规则写入 /etc/realm/pool_full.json
  - 生成 /etc/realm/config.json
  - 重启 realm 服务生效
```

### 2.2 关键设计（建议理解）

- `Push-report` 模型：Agent 主动上报，Panel 不依赖常驻反向直连
- `Desired / Ack` 双版本：避免错配与重复下发
- `命令签名`：HMAC + ts + nonce，防篡改、防重放
- `失败回退`：Panel 直连失败时改为“排队等待 Agent 上报执行”

这使 Nexus 在“私网/弱网/高延迟”环境下仍可用。

---

## 3. 10 分钟快速开始

### 3.1 安装 Panel

```bash
bash <(curl -fsSL https://nexus.infpro.me/nexus/realm_panel.sh || curl -fsSL https://raw.githubusercontent.com/cyeinfpro/NexusControlPlane/main/realm_panel.sh)
```

安装脚本会交互引导你完成：

- 安装模式（在线/离线）
- 面板账号初始化
- 面板端口（默认 `6080`）
- 面板公网地址与资产来源策略（`panel` 或 `github`）

### 3.2 登录 Panel

- 打开 `http://<PanelIP>:6080`
- 使用安装时设置的账号密码登录

### 3.3 创建节点并接入 Agent

1. 在面板创建节点
2. 打开节点详情页
3. 执行“接入命令”（推荐）

你也可以手动接入（Linux 示例）：

```bash
curl -fsSL -H "X-Join-Token: <NODE_API_KEY>" "http://<PANEL_HOST>:6080/join" | sudo bash
```

> `<NODE_API_KEY>` 是该节点在面板中的 API Key。

### 3.4 新建第一条普通转发规则

在节点详情页新增规则：

- 监听：`0.0.0.0:33060`
- 目标：`10.0.0.11:3306`、`10.0.0.12:3306`
- 协议：`tcp`
- 负载：`roundrobin`

保存后面板会自动下发并触发 apply。

---

## 4. 核心概念（必须先理解）

### 4.1 节点（Node）

每个节点包含：

- `base_url`：Panel 访问 Agent 的地址
- `api_key`：Panel 调 Agent API 的认证凭据
- `verify_tls`：是否校验证书
- `is_private`：是否私网节点（影响文件管理与队列策略）
- `role`：`normal`（普通）或 `website`（网站机）
- `system_type`：`auto`/`linux`/`macos`/`windows`

### 4.2 规则池（Pool）

规则以 `pool.endpoints[]` 组织，每个 endpoint 表示一条转发规则。

### 4.3 desired_version / ack_version

- Panel 持有 desired 配置版本
- Agent 执行后回传 ack 版本
- 版本不一致时，Panel 会继续驱动同步

### 4.4 同步规则（WSS / 内网）

这两类规则是“成对”的：

- 发送侧（sender/server）
- 接收侧（receiver/client）

系统通过 `sync_id` 绑定双端，默认锁定接收侧规则，防止误改。

---

## 5. 功能总览（按模块）

## 5.1 控制台与节点管理

### 功能说明

- 节点增删改查
- 分组与排序
- 节点在线状态（基于上报新鲜度）
- 一键接入/卸载脚本
- 节点角色与系统类型管理
- 节点自动重启策略配置（天/周/月）

### 怎么使用

1. 控制台新增节点
2. 选择分组、是否私网、是否网站机
3. 在节点详情页执行接入
4. 使用 `Ping/Trace` 验证连通性

### 示例

- 新建“北京-转发-01”，分组“北京”，`is_private=false`
- 新建“上海-网站-01”，分组“上海”，`role=website`

## 5.2 规则编排与发布

### 功能说明

- 普通转发：TCP / UDP / TCP+UDP
- WSS 隧道：双端自动编排
- 内网穿透：公网入口 + 私网出口自动编排
- 单条删除 / 批量保存 / 异步任务
- 静态校验 + 运行时预检

### 怎么使用

1. 在节点页新增/编辑规则
2. 保存时系统会先做校验
3. 校验通过后写入 desired pool
4. Agent 执行并 ACK

## 5.3 QoS 与自适应负载

### 功能说明

支持端口级 QoS：

- 带宽限制：`bandwidth_kbps`
- 最大连接：`max_conns`
- 新建连接速率：`conn_rate`
- 总流量阈值：`traffic_total_bytes`

支持自适应权重（Adaptive LB）：

- 基于可达率、延迟、错误率、连续失败自动调权
- 有冷却时间与最小变化阈值，避免抖动

### 怎么使用

- 在规则高级参数配置 QoS
- 保持多目标 `remotes`，启用 `roundrobin` 或 `random_weight` 权重
- 观察 stats 中目标健康与权重变化

## 5.4 观测与诊断

### 功能说明

- 规则实时指标：流量、连接、健康
- 节点系统指标：CPU/内存/磁盘/网络/在线时长
- 路由追踪（trace）
- 持久化历史曲线（Panel DB）

### 怎么使用

1. 在节点详情页打开统计面板
2. 切换到历史窗口查看趋势
3. 异常时使用 Trace 定位路径问题

## 5.5 NetMon 网络波动监控

### 功能说明

- 支持 `ping` / `tcping`
- 一个监控项可绑定多个节点
- 阈值分级：`warn_ms` / `crit_ms`
- 支持只读分享与大屏墙
- 支持固定时间窗口分享

### 怎么使用

1. 新建监控项（目标、模式、节点、阈值）
2. 在 `/netmon` 查看快照
3. 通过分享链接输出只读视图

## 5.6 网站管理

### 功能说明

- 站点类型：`static` / `php` / `reverse_proxy`
- 节点环境：安装/卸载 nginx、php-fpm、acme.sh
- SSL：申请、续期、失败回退队列
- HTTPS 强制跳转开关
- 健康巡检 + 诊断记录

### 怎么使用

1. 把节点角色设为网站机（`role=website`）
2. 新建站点（域名、类型、根目录或代理地址）
3. 申请证书
4. 在诊断页查看健康事件

## 5.7 文件管理与分享

### 功能说明

- 文件列表、读写、删除、解压
- 分片上传、上传续传状态
- 文件/目录下载（目录 ZIP）
- 收藏夹
- 短链分享、过期控制、撤销

私网节点策略：

- 默认走队列模式（任务投影）
- 可配置“直连隧道”让文件管理走实时直连

### 怎么使用

1. 进入 `网站 -> 文件管理`
2. 执行上传、编辑、下载等操作
3. 需要外发时使用“分享链接”

## 5.8 备份与恢复

### 功能说明

- 单节点规则备份/恢复
- 全量备份（ZIP）
- 全量恢复（后台任务 + 进度）

全量备份包含（关键）：

- 节点与规则
- 站点配置与文件
- 证书元数据
- NetMon 监控与样本
- 用户/角色与权限数据
- 文件分享状态与收藏

## 5.9 权限与审计

### 功能说明

内置角色（RBAC）：

- `owner`
- `admin`
- `operator`
- `forwarder`
- `viewer`

支持子账号策略：

- 可见节点范围
- 可用隧道类型（direct/wss/intranet）
- 月流量上限

审计日志记录“谁在何时对哪个节点做了什么操作”。

---

## 6. 规则系统详细说明（普通转发 / WSS / 内网穿透）

## 6.1 普通转发规则字段说明

一条普通规则常见字段：

- `listen`：监听地址，如 `0.0.0.0:8080`
- `remotes`：目标列表，如 `10.0.0.10:80`
- `protocol`：`tcp` / `udp` / `tcp+udp`
- `balance`：`roundrobin` / `random_weight` / `iphash` / `least_conn` / `least_latency` / `consistent_hash`
- 权重仅 `roundrobin` 与 `random_weight` 生效（格式：`algo: 3,1,2`）
- `least_latency` 会基于实时 `RTT/jitter/loss` 综合评分进行选路（不是只看“可用/不可用”）
- 普通转发的 `remote/remotes` 支持域名（`host:port`）；Agent 会周期解析并自动刷新运行目标池（默认 `60s`，可用 `REALM_AGENT_DNS_REFRESH_INTERVAL` 调整）
- 当 remote 主机名形如 `_service._tcp.example.com` 时，Agent 会优先执行 DNS SRV 解析，并按 SRV 权重展开目标地址池
- `remote` 为域名且解析出多地址时，内网穿透数据面默认启用 Happy Eyeballs 拨号竞速（并行尝试并选择最快可用地址）
- `iptables` 工具仅支持 `roundrobin` / `random_weight`；其余算法请切换 `realm` 工具
- `disabled`：是否禁用
- `network.qos`：QoS 参数
- `remark`：备注
- `favorite`：收藏

### 示例：普通转发（含 QoS）

```json
{
  "pool": {
    "endpoints": [
      {
        "listen": "0.0.0.0:33060",
        "remotes": [
          "10.0.0.11:3306",
          "10.0.0.12:3306"
        ],
        "protocol": "tcp",
        "balance": "roundrobin: 3, 1",
        "disabled": false,
        "network": {
          "qos": {
            "bandwidth_kbps": 204800,
            "max_conns": 3000,
            "conn_rate": 300,
            "traffic_total_bytes": 1099511627776
          }
        },
        "remark": "MySQL 主从转发"
      }
    ]
  }
}
```

## 6.2 WSS 隧道规则（双端自动生成）

### 说明

调用 `/api/wss_tunnel/save` 后，系统会：

- 在发送节点写入 sender 规则
- 在接收节点写入 receiver 规则
- 两端绑定同一个 `sync_id`
- 接收侧默认锁定，防止手工误改

### 示例：保存 WSS 隧道

```json
{
  "sender_node_id": 1,
  "receiver_node_id": 2,
  "listen": "0.0.0.0:18080",
  "receiver_port": 28080,
  "remotes": [
    "172.16.1.10:80",
    "172.16.1.11:80"
  ],
  "protocol": "tcp",
  "balance": "roundrobin",
  "wss": {
    "host": "wss.example.com",
    "path": "/edge/ws",
    "sni": "wss.example.com",
    "tls": true,
    "insecure": false
  },
  "qos": {
    "bandwidth_mbps": 200,
    "max_conns": 5000,
    "conn_rate": 800
  }
}
```

## 6.3 内网穿透规则（公网入口 + 私网出口）

### 说明

调用 `/api/intranet_tunnel/save` 后，系统会：

- 公网节点生成 `server` 侧规则
- 私网节点生成 `client` 侧规则
- 自动管理 token、证书与 TLS 校验
- 支持 ACL

> 注意：`receiver_node_id` 必须是 `is_private=true` 的节点。

### 示例：保存内网穿透

```json
{
  "sender_node_id": 10,
  "receiver_node_id": 21,
  "listen": "0.0.0.0:15443",
  "server_host": "edge.example.com",
  "server_port": 18443,
  "remotes": [
    "10.10.0.5:443"
  ],
  "protocol": "tcp",
  "balance": "roundrobin",
  "token": "nexus-intranet-token-001",
  "intranet_tls_verify": true,
  "acl": {
    "allow_sources": ["203.0.113.0/24"],
    "deny_sources": ["0.0.0.0/0"],
    "allow_hours": ["09:00-18:00"],
    "allow_tokens": ["office-shift"]
  },
  "qos": {
    "bandwidth_mbps": 100,
    "max_conns": 1500
  }
}
```

## 6.4 发布与预检机制

保存规则时会做两层检查：

1. 静态校验
- 监听地址格式
- 端口冲突
- balance/weights 匹配
- 规则结构合法性

2. 运行时预检（可配置开关）
- 调 Agent `/api/v1/netprobe` 进行目标可达性与依赖检测
- 返回 warning，不直接阻塞全部流程（除硬错误）

---

## 7. 网站管理详细说明

## 7.1 站点类型

- `static`：静态站点
- `php`：PHP 站点
- `reverse_proxy`：反向代理站点（必须填写 `proxy_target`）

## 7.2 创建站点流程

1. 选择网站机节点（`role=website`）
2. 输入域名列表
3. 选择站点类型
4. 填写 `root_path` 或 `proxy_target`
5. 提交后进入后台任务执行（对私网节点尤为重要）

### 示例：反向代理站点

- 域名：`api.example.com`
- 类型：`reverse_proxy`
- 目标：`http://127.0.0.1:9000`
- HTTPS 跳转：开启

## 7.3 SSL 证书管理

支持：

- 申请：`/websites/{site_id}/ssl/issue`
- 续期：`/websites/{site_id}/ssl/renew`

策略：

- 公网可达节点优先直连执行
- 失败可自动回退队列
- 私网节点默认直接走队列

## 7.4 站点健康与诊断

- 后台健康巡检（默认开启）
- 诊断页支持实时诊断与历史事件查看
- 记录状态变更（失败、恢复）

---

## 8. 文件管理与分享详细说明

## 8.1 文件管理能力

- 列表：`list`
- 读取：`read`
- 写入：`write`
- 创建目录：`mkdir`
- 删除：`delete`
- 上传（分片与兼容模式）
- 解压：`unzip`
- 下载（单文件/目录打包）

## 8.2 私网节点文件模式

默认逻辑：

- 私网节点走队列模式（不会阻塞前端）
- 非私网节点走直连 Agent 文件 API

可选增强：

- 配置“节点直连隧道”后，私网节点文件管理可切到直连模式
- 若私网节点 `base_url` 是面板本机回环地址（如 `127.0.0.1`），可自动走直连
- 由 `REALM_WEBSITE_PRIVATE_FILES_DIRECT_ALLOW_LOOPBACK` 控制（默认开启）

## 8.3 文件分享

支持：

- 短链分享
- 过期时间控制（TTL）
- 主动撤销
- 多文件/目录打包下载

默认限制：

- TTL 最小 300 秒
- TTL 默认 86400 秒（1 天）
- 单次最多分享 200 项

### 示例：分享 2 个路径

```json
{
  "items": [
    {"path": "release/app.tar.gz", "is_dir": false},
    {"path": "release/docs", "is_dir": true}
  ],
  "ttl_sec": 3600
}
```

---

## 9. 备份与恢复详细说明

## 9.1 单节点规则备份

- 入口：`GET /api/nodes/{node_id}/backup`
- 输出：该节点规则 JSON

## 9.2 全量备份

- 启动：`POST /api/backup/full/start`
- 进度：`GET /api/backup/full/progress?job_id=...`
- 下载：`GET /api/backup/full/download?job_id=...`

## 9.3 全量恢复

- 启动：`POST /api/restore/full/start`
- 进度：`GET /api/restore/full/progress?job_id=...`

恢复过程会分阶段执行，并有超时保护与失败回传。

> 强烈建议：恢复前先做一次新备份。

---

## 10. 权限、账号与审计

## 10.1 账号体系

- 首次启动通过 `/setup` 初始化 owner
- 密码采用 PBKDF2-SHA256
- Session 与分享 Token 使用同一 `SECRET_KEY` 签名

## 10.2 内置角色（系统默认）

- `owner`：全部权限
- `admin`：管理权限（不含用户/角色管理）
- `operator`：运维权限（节点/发布/网站）
- `forwarder`：仅转发与发布相关
- `viewer`：只读

## 10.3 子账号策略

- 可访问节点白名单
- 可使用隧道类型白名单（direct/wss/intranet）
- 月流量上限

## 10.4 审计日志

记录：

- 操作者
- 操作动作
- 节点与上下文信息
- 来源 IP
- 时间戳

---

## 11. Agent 生命周期管理（升级/自动重启/时间同步）

## 11.1 一键升级全部 Agent

- 查询最新版本：`GET /api/agents/latest`
- 发起全量升级：`POST /api/agents/update_all`
- 查询进度：`GET /api/agents/update_progress`

升级任务支持重试、超时与离线过期。

## 11.2 节点自动重启策略

支持策略：

- `daily`
- `weekly`
- `monthly`

参数：

- `interval`（周期）
- `hour:minute`（执行时间）
- `weekdays` / `monthdays`

## 11.3 节点时间同步策略

可在面板设置下发时间同步策略：

- 时区设置
- NTP 开关
- 是否设置系统时钟

---

## 12. 安装部署（生产建议）

## 12.1 Panel 安装（推荐）

```bash
bash <(curl -fsSL https://nexus.infpro.me/nexus/realm_panel.sh || curl -fsSL https://raw.githubusercontent.com/cyeinfpro/NexusControlPlane/main/realm_panel.sh)
```

脚本菜单：

1. 安装面板
2. 更新面板
3. 重启面板
4. 卸载面板

默认目录：

- `/opt/realm-panel`
- `/etc/realm-panel`

## 12.2 Linux Agent 安装

优先方式：执行面板生成的接入命令。

手动方式（示例）：

```bash
curl -fsSL -H "X-Join-Token: <NODE_API_KEY>" "http://<PANEL_HOST>:6080/join" | sudo bash
```

默认端口：`18700`

## 12.3 macOS Agent 安装

```bash
sudo bash <(curl -fsSL <PANEL_BASE_URL>/static/realm_agent_macos.sh)
```

安装后服务标签：

- `com.realm.agent`
- `com.realm.agent.revtunnel`（可选）

> macOS 节点在前端默认仅暴露内网穿透模式。

## 12.4 私网文件直连（反向隧道）

场景：Panel 无法稳定直连私网 Agent，希望文件管理改为实时目录。

核心思路：

- 私网节点通过 `ssh -R` 把本地 Agent 端口映射到面板机回环端口
- 节点 `base_url` 写成面板机 `127.0.0.1:<映射端口>`

服务文件参考：

- `/Users/liangchanghua/Downloads/nexus/agent/systemd/realm-agent-revtunnel.service`
- `/Users/liangchanghua/Downloads/nexus/agent/systemd/revtunnel.env.example`

---

## 13. API 实战示例

> Panel API 需要登录会话（Cookie）；Agent API 需要 `X-API-Key`。

## 13.1 Agent：查看规则池

```bash
curl -sS \
  -H "X-API-Key: $(cat /etc/realm-agent/api.key)" \
  http://127.0.0.1:18700/api/v1/pool
```

## 13.2 Agent：触发 apply

```bash
curl -sS \
  -H "X-API-Key: $(cat /etc/realm-agent/api.key)" \
  -X POST \
  http://127.0.0.1:18700/api/v1/apply
```

## 13.3 Agent：查看实时统计

```bash
curl -sS \
  -H "X-API-Key: $(cat /etc/realm-agent/api.key)" \
  http://127.0.0.1:18700/api/v1/stats
```

## 13.4 Panel：保存某节点规则池（示例）

```bash
curl -sS -X POST "http://<PANEL_HOST>:6080/api/nodes/1/pool" \
  -H "Content-Type: application/json" \
  -H "Cookie: realm_panel_sess=<YOUR_SESSION_COOKIE>" \
  -d '{
    "pool": {
      "endpoints": [
        {
          "listen": "0.0.0.0:18080",
          "remotes": ["10.0.0.21:8080"],
          "protocol": "tcp",
          "balance": "roundrobin",
          "disabled": false
        }
      ]
    }
  }'
```

## 13.5 Panel：创建 NetMon 监控项

```bash
curl -sS -X POST "http://<PANEL_HOST>:6080/api/netmon/monitors" \
  -H "Content-Type: application/json" \
  -H "Cookie: realm_panel_sess=<YOUR_SESSION_COOKIE>" \
  -d '{
    "target": "1.1.1.1",
    "mode": "ping",
    "interval_sec": 5,
    "warn_ms": 120,
    "crit_ms": 300,
    "node_ids": [1,2,3],
    "enabled": true
  }'
```

## 13.6 Panel：发起全量备份

```bash
curl -sS -X POST "http://<PANEL_HOST>:6080/api/backup/full/start" \
  -H "Cookie: realm_panel_sess=<YOUR_SESSION_COOKIE>"
```

---

## 14. 常用配置项（环境变量）

说明：

- Panel 大部分配置是“数据库设置优先，环境变量兜底”
- 读取顺序：Panel Setting > Env > Default

## 14.1 Panel 核心配置（常用）

| 变量 | 默认值 | 说明 |
|---|---:|---|
| `REALM_PANEL_HOST` | `0.0.0.0` | Panel 监听地址 |
| `REALM_PANEL_PORT` | `6080` | Panel 监听端口 |
| `REALM_PANEL_DB` | `/etc/realm-panel/panel.db` | SQLite 路径 |
| `REALM_PANEL_PUBLIC_URL` | 空 | 对外访问基地址（脚本/分享用） |
| `REALM_PANEL_ASSET_SOURCE` | `panel` | Agent 安装资产来源：`panel` / `github` |
| `REALM_PANEL_LOG_FILE` | `/var/log/realm-panel/panel.log` | 运行日志 |
| `REALM_PANEL_CRASH_LOG_FILE` | `/var/log/realm-panel/crash.log` | 崩溃日志 |
| `REALM_NETMON_SHARE_PUBLIC` | `1` | 是否允许 NetMon 公开分享 |
| `REALM_NETMON_SHARE_TTL_SEC` | `604800` | NetMon 分享默认 TTL（7 天） |

## 14.2 Panel 观测与任务（常用）

| 变量 | 默认值 | 说明 |
|---|---:|---|
| `REALM_STATS_HISTORY_ENABLED` | `1` | 规则历史采样开关 |
| `REALM_STATS_HISTORY_INTERVAL_SEC` | `10` | 历史采样间隔（秒） |
| `REALM_STATS_HISTORY_RETENTION_DAYS` | `7` | 历史保留天数 |
| `REALM_NETMON_BG_ENABLED` | `1` | NetMon 后台任务开关 |
| `REALM_NETMON_RETENTION_DAYS` | `7` | NetMon 样本保留天数 |
| `REALM_SITE_MONITOR_ENABLED` | `1` | 站点健康巡检开关 |
| `REALM_SITE_MONITOR_INTERVAL` | `60` | 站点巡检周期（秒） |
| `REALM_SAVE_PRECHECK_ENABLED` | `1` | 保存前运行时预检开关 |
| `REALM_SYNC_SAVE_PRECHECK_ENABLED` | `1` | 隧道同步预检开关 |

## 14.3 Agent 核心配置（常用）

| 变量 | 默认值 | 说明 |
|---|---:|---|
| `REALM_AGENT_HOST` | `0.0.0.0` | Agent 监听地址 |
| `REALM_AGENT_PORT` | `18700` | Agent 监听端口 |
| `REALM_PANEL_URL` | 空 | Agent 上报 Panel 地址 |
| `REALM_AGENT_ID` | 空 | 节点 ID（上报用） |
| `REALM_AGENT_HEARTBEAT_INTERVAL` | `30`（安装脚本常设 3） | 上报周期 |
| `REALM_AGENT_REPORT_INSECURE_TLS` | `0` | 上报时是否忽略 TLS 验证 |
| `REALM_AGENT_AUTO_APPLY` | `1` | 下发后自动 apply |
| `REALM_PANEL_VERIFY_TLS` | `0` | Agent 访问 Panel 是否校验证书 |

## 14.4 Agent 文件与内网穿透调优（常用）

| 变量 | 默认值 | 说明 |
|---|---:|---|
| `REALM_AGENT_UNZIP_MAX_ENTRIES` | `20000` | 解压条目上限 |
| `REALM_AGENT_UNZIP_MAX_TOTAL_BYTES` | `5GB` | 解压总量上限 |
| `REALM_INTRANET_SOCKET_RCVBUF` | `1048576` | 隧道接收缓冲 |
| `REALM_INTRANET_SOCKET_SNDBUF` | `1048576` | 隧道发送缓冲 |
| `REALM_INTRANET_TCP_NODELAY` | `1` | 低延迟发送 |
| `REALM_INTRANET_TCP_RELAY_CHUNK` | `131072` | TCP 中继分块 |
| `REALM_WEBSITE_PRIVATE_FILES_DIRECT_ALLOW_LOOPBACK` | `1` | 私网节点回环地址是否允许直连文件管理 |

---

## 15. 关键目录与文件

## 15.1 Panel

- 程序目录：`/opt/realm-panel/panel`
- DB：`/etc/realm-panel/panel.db`
- 凭据：`/etc/realm-panel/credentials.json`
- Secret：`/etc/realm-panel/secret.key`
- 环境变量：`/etc/realm-panel/panel.env`
- systemd：`/etc/systemd/system/realm-panel.service`

## 15.2 Agent

- 程序目录：`/opt/realm-agent/agent`
- API Key：`/etc/realm-agent/api.key`
- 上报配置：`/etc/realm-agent/panel.env`
- Agent 环境：`/etc/realm-agent/agent.env`
- 规则池（完整）：`/etc/realm/pool_full.json`
- 规则池（运行）：`/etc/realm/pool.json`
- realm 配置：`/etc/realm/config.json`
- ACK：`/etc/realm-agent/panel_ack.version`

---

## 16. 常用运维命令

## 16.1 Panel

```bash
systemctl status realm-panel --no-pager
journalctl -u realm-panel -f
```

## 16.2 Agent

```bash
systemctl status realm-agent --no-pager
journalctl -u realm-agent -f

systemctl status realm --no-pager
journalctl -u realm -e
```

## 16.3 macOS Agent

```bash
launchctl print system/com.realm.agent
launchctl print system/com.realm.agent.revtunnel
```

---

## 17. 故障排查手册

## 17.1 节点显示离线

检查顺序：

1. Agent 服务是否运行
2. `REALM_PANEL_URL` / `REALM_AGENT_ID` 是否正确
3. Agent 是否能访问 Panel `/api/agent/report`
4. TLS 是否因证书问题被拒绝（必要时启用上报不校验）

## 17.2 保存规则失败

常见原因：

- listen 格式错误
- 端口冲突
- remotes 空或格式不合法
- 同步锁定规则被手工修改

处理建议：

- 先看返回的 `issues`
- 若是同步规则，回到发送侧节点操作

## 17.3 私网节点文件管理“看不到实时目录”

这是默认行为（队列投影模式）。

如果你需要实时目录：

- 配置节点直连隧道
- 或将 `base_url` 指向有效回环映射端口

## 17.4 SSL 申请失败

排查：

1. 域名解析是否指向对应节点
2. 80/443 是否可达
3. nginx 配置是否被其他服务抢占
4. 节点是否在私网队列模式（等待上报执行）

## 17.5 全量恢复失败

排查：

- 备份包是否完整
- 站点文件量是否过大（超上传限制）
- 节点连通性是否稳定
- 查看恢复任务进度详情中的失败阶段

---

## 18. 本地开发运行

## 18.1 Panel

```bash
cd panel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 6080
```

## 18.2 Agent

```bash
cd agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 18700
```

---

## 19. 安全建议

- 生产环境务必开启 HTTPS 与证书校验
- 面板与 Agent API Key 不要明文外泄
- 备份文件包含敏感信息，必须按密级存储与传输
- 分享链接设置短 TTL，使用后及时撤销
- 仅开放必要端口，禁止无关来源访问 Agent API
- 使用最小权限账号进行日常运维

---

## 20. 免责声明

本项目提供网络转发、站点运维与自动化编排能力。请确保在合法合规场景下使用，并自行承担部署、配置与运行风险。
