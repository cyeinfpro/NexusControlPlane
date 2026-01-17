# Realm Pro Suite v15

此版本重点修复/调整：

- ✅ **安装不再要求设置用户名/密码**：默认无登录界面，打开即用。
- ✅ **配对码只用于 WSS 参数同步**：不再用于“绑定/链接机器”。

## 组件说明

- **Agent**：运行在每台节点上，提供本地 API（Bearer Token 鉴权）。
- **Panel**：统一 Web 管理面板，可管理多个 Agent。

## 快速安装

### 1) 安装 Agent

```bash
bash realm_agent.sh
```

脚本会输出一个 `Agent Token`，请复制保存。

### 2) 安装 Panel

```bash
bash realm_panel.sh
```

安装完成后会提示访问地址。

### 3) 在面板添加节点

打开面板首页 → **添加节点**，填入：

- 节点名称：随便写（例如 `HK-1`）
- Agent 地址：例如 `http://10.0.0.2:6080`
- Token：粘贴 Agent 安装脚本输出的 token
- TLS 验证：如果你用自签证书跑 https，可以取消勾选（默认勾选）

添加完成后，点击节点即可进入规则管理。

## WSS 对接码如何用

- 在 **WSS 服务端（Server）** 创建规则后，面板会返回一个 **对接码**。
- 在 **WSS 客户端（Client）** 创建规则时，填写这个对接码，面板会自动把 Host/Path/SNI/Insecure 参数填好。

> 对接码只用于 WSS 参数同步，与“链接机器/绑定 Agent”无关。

