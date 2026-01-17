# Realm Pro Suite (v19)

一套可上生产的 `Realm` 转发管理套件：

- **Agent**：部署在每台被控机上，提供 HTTP API，负责写入 `realm.toml`、暂停/删除规则、查看目标健康状态等。
- **Panel**：部署在管理机上，通过 Web UI 管理多个 Agent 节点，支持 **WSS 配对码自动填参**。

---

## 目录结构（请保持不变）

```
.
├─ agent/
├─ panel/
├─ realm_agent.sh
└─ realm_panel.sh
```

---

## 安装 Agent（被控机）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cyeinfpro/Realm/refs/heads/main/realm_agent.sh)
```

安装完成后会输出：
- Agent 监听地址（默认端口：18700）
- Agent Token（添加节点时需要）

---

## 安装 Panel（管理机）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/cyeinfpro/Realm/refs/heads/main/realm_panel.sh)
```

安装过程中会要求输入：
- 面板端口（默认 6080）
- 用户名（默认 admin）
- 密码（必须设置）

---

## 配对码说明（非常重要）

**配对码用于 WSS 发送端自动获取 WSS 参数（host/path/sni/insecure），不是用来“链接机器”的。**

- 当你在 Panel 创建 **WSS 接收端（wss_recv）** 规则时，会生成一个配对码
- 之后创建 **WSS 发送端（wss_send）** 规则时，填入该配对码即可自动回填参数

---

## Fork 后如何替换仓库地址

如果你 fork 了仓库，只需要在两个安装脚本开头修改下面三行：

```bash
REPO_OWNER="你的用户名"
REPO_NAME="你的仓库名"
REPO_BRANCH="main"
```

不要修改其它路径。

---

## 常用命令

```bash
systemctl status realm-agent --no-pager
journalctl -u realm-agent -n 200 --no-pager

systemctl status realm-panel --no-pager
journalctl -u realm-panel -n 200 --no-pager
```
