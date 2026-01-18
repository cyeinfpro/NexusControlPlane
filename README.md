# Realm Pro Suite v21

Web Panel + Agent for managing `realm` forwarding rules.

## ✅ Key behaviors

- Panel install asks for **login username & password**.
- **Pairing Code** is used **ONLY** for syncing WSS sender parameters (Host / Path / SNI / Insecure).
- Linking a machine to Panel is done with **Agent Token** (NOT pairing code).

## ✅ Repo layout (MUST be in repo root)

```
.
├── agent/
├── panel/
├── realm_agent.sh
├── realm_panel.sh
└── README.md
```

## Install

### Panel (controller)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/refs/heads/<BRANCH>/realm_panel.sh)
```

### Agent (node)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/refs/heads/<BRANCH>/realm_agent.sh)
```

## Change your GitHub repo address

Edit the top of these two files:

- `realm_panel.sh`
- `realm_agent.sh`

Change:

```bash
REPO_OWNER="cyeinfpro"
REPO_NAME="Realm"
REPO_BRANCH="main"
```

## Ports

- Panel default: `6080`
- Agent default: `18700`

