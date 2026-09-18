---
name: secret-drop
description: "Passwords or API keys sent through Telegram, Discord, or Slack, or masked by OpenClaw: request a Password Pusher or SnapPwd link and ingest it without exposing plaintext."
---

# secret-drop

Silently ingest one-time secret links into OpenClaw without leaking credentials into chat transcripts, execution arguments, logs, or model context.

## Why This Skill Exists

In modern OpenClaw releases, secret redaction is mandatory and permanently enabled. Typing passwords or API keys directly into a messenger chat (Telegram, Discord, Slack) causes OpenClaw's redaction engine to irrevocably mask the tokens (e.g. `sk-or-...` becomes `***` or `sk-or-…4a2b`) before persisting to transcript history. Subsequent turns and agent tools only receive the masked values, breaking upstream authentication.

Furthermore, on messenger channels without a public Control UI origin, official masked credential requests fail because no reachable web form can be opened.

`secret-drop` solves this by decoupling the secret from the chat channel:
1. The operator enters the secret into an existing self-destructing link service (Password Pusher or SnapPwd).
2. The operator drops only the single-use link into the chat.
3. The agent invokes the silent ingest CLI.
4. The CLI fetches the payload in-process and writes it directly and atomically to the target destination (e.g. `~/.openclaw/.env`, project `.env`, or OpenClaw SQLite secret store). A provider configured for one retrieval consumes or expires the drop.
5. The CLI prints only secret-free metadata (`ok: true`, byte count, target name). The plaintext never touches standard output, transcript storage, or model context.

## Supported Providers

| Provider | URL Pattern | Zero Knowledge | Engine | Notes |
|---|---|---|---|---|
| **Password Pusher** | `https://pwpush.com/p/...` or custom domain | Server-encrypted | Native JSON API | Enable the 1-click retrieval step so messaging link-preview crawlers don't burn the link! |
| **SnapPwd** | `https://snappwd.io/g/...#<key>` | Yes (AES-GCM in browser) | Native AES-GCM decrypt | Key is in the `#` fragment and never reaches the server. |

*Note:* Password Pusher and SnapPwd use native in-process HTTPS and AES-GCM decryption without child process delegation, avoiding command-line secret exposure.

## Destinations

- `openclaw-env`: Global OpenClaw daemon environment (`~/.openclaw/.env`). Recommended for provider keys like `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, etc.
- `openclaw-store`: OpenClaw team SQLite secret store (`openclaw secrets store set <NAME> --kind secret`).
- `dotenv`: Local project `.env` file (e.g. `/home/cleo/projects/my-app/.env`).
- `file`: Raw mode-0600 file for service account JSON or PEM private keys.

## Quick Start for Operators

When sending a credential over Telegram or Discord:

1. Open [pwpush.com](https://pwpush.com) or [snappwd.io](https://snappwd.io).
2. Paste the API key or password.
3. Set expiration to **1 view** and **1 day**.
4. If using Password Pusher, check **1-Click Retrieval Step** (crucial for Telegram/Slack).
5. Send the link to the agent along with the desired environment variable name:
   > "Here is the key for OPENROUTER_API_KEY: https://pwpush.com/p/abcdef123456"

## Agent Ingest Workflow

When an authorized operator provides a one-time link and an exact destination, resolve this skill directory from the loaded `SKILL.md`, then run its bundled silent launcher:

```bash
python3 <skill-directory>/scripts/secret-drop ingest "<URL>" \
  --name "VARIABLE_NAME" \
  --to openclaw-env \
  --restart-gateway \
  --json
```

`--restart-gateway` is optional. It invokes the supported `openclaw gateway restart
--safe` path only when the destination reports that a restart is required. Omit it
when the operator wants to control restart timing manually.

Output on stdout:
```json
{"bytes":64,"created":false,"destination":"openclaw-env","name":"OPENROUTER_API_KEY","ok":true,"path":"/home/alice/.openclaw/.env","provider":"pwpush","replaced":true,"restart_required":true}
```

The agent verifies `"ok": true` and reports back to the user:
> "OPENROUTER_API_KEY has been stored securely in ~/.openclaw/.env (64 bytes). The link was consumed and destroyed."

## Security Rules

1. **NEVER echo or cat the secret.** Do not run `cat ~/.openclaw/.env` or print the value in chat.
2. **Atomic writes only.** The CLI uses `mkstemp`, `fchmod 0600`, and atomic rename so no partial or world-readable files ever exist.
3. **No stdout leaks.** The CLI strictly suppresses payload bodies on all stdout/stderr channels.
4. **SSRF protection.** The HTTP fetcher blocks the request when any resolved A/AAAA record is loopback, link-local, private, scoped, or otherwise non-global unless `--allow-private-host` is explicitly provided.
5. **Treat links as bearer capabilities.** Accept them only from an authorized operator, consume them promptly, and never repost an unconsumed link.
6. **Do not claim activation too early.** `openclaw-env` reports `restart_required: true`; use `--restart-gateway` only when restart authorization is part of the task, otherwise report that a restart remains required.
