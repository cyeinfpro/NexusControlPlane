# Realm Pro Suite v18

> 一套可在多台 Debian/Ubuntu 服务器上部署的 **Realm 转发管理套件**：
> - **Agent**：被控机 API（管理 Realm 规则、生成配置、应用重启、状态/连接数）
> - **Panel**：Web 管理面板（登录鉴权、节点管理、规则增删改、暂停、日志查看、WSS 配对码）

## 仓库结构（必须是这个结构）

```
.
├── agent/
│   ├── app/
│   ├── requirements.txt
│   └── systemd/realm-agent.service
├── panel/
│   ├── app/
│   ├── requirements.txt
│   └── systemd/realm-panel.service
├── realm_agent.sh
└── realm_panel.sh
```

> 说明：安装脚本通过 **GitHub Archive** 下载仓库源码，自动识别 `agent/` 与 `panel/` 目录。

## 一键安装

### 1) 在被控机安装 Agent

```bash
curl -fsSL https://raw.githubusercontent.com/cyeinfpro/Realm/refs/heads/main/realm_agent.sh | bash
```

安装完成后会输出：
- Agent API 地址（如 `http://IP:18700`）
- Token

### 2) 在主控机安装 Panel

```bash
curl -fsSL https://raw.githubusercontent.com/cyeinfpro/Realm/refs/heads/main/realm_panel.sh | bash
```

安装过程中会要求输入：
- 面板端口
- 登录用户名
- 登录密码

### 3) 在面板中添加节点

打开：`http://<PanelIP>:6080`
- 节点名称
- Agent 地址
- Agent Token

即可管理。

## WSS 配对码逻辑（关键）

- **配对码不是用来链接机器的。**
- 配对码用于：当你创建 **WSS 接收端** 时，自动生成一个配对码；之后创建 **WSS 发送端** 时，粘贴该配对码即可自动填充 `Host/Path/SNI/Insecure`。

## 排错

- 面板日志：
  ```bash
  journalctl -u realm-panel -n 200 --no-pager
  ```

- Agent 日志：
  ```bash
  journalctl -u realm-agent -n 200 --no-pager
  ```

- Realm 日志：
  ```bash
  journalctl -u realm -n 200 --no-pager
  ```
