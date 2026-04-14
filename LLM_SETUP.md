# Local LLM Setup (Optional — for natural-language command parsing)

The tool works 100% **without** a local LLM — the deterministic parser handles
`check dlp`, `why FW-01`, `bypass`, and many natural phrasings. The LLM is only
needed if you want free-form sentences like *"Hey, can you see if my cloud
firewall looks reasonable?"* to parse reliably.

**Nothing leaves your machine.** The assessment tool only talks to
`127.0.0.1:11434` (Ollama's loopback port). The LLM runs locally; no prompts,
no credentials, no tenant data ever egress.

---

## One-time setup (~10 minutes on first run)

### 1. Install Ollama

| OS | Command |
| --- | --- |
| **Windows** | Download from https://ollama.com/download — run the installer |
| **macOS**   | Download from https://ollama.com/download — drag to Applications |
| **Linux**   | `curl -fsSL https://ollama.com/install.sh \| sh` |

After installation Ollama runs as a background service on `127.0.0.1:11434`.

### 2. Pull a model

Open a terminal (PowerShell / Terminal / bash) and run **one** of these:

| Model | Size | When to pick |
| --- | --- | --- |
| `ollama pull llama3.1`     | ~4.7 GB | Default. Good accuracy on command intent. |
| `ollama pull llama3.2:3b`  | ~2.0 GB | Smaller, faster, still solid for short commands. |
| `ollama pull phi3`         | ~2.3 GB | Microsoft's small model — low memory footprint. |
| `ollama pull qwen2.5:3b`   | ~1.9 GB | Excellent for structured / JSON output. |

The tool defaults to `llama3.1`. If you pulled a different one, change the model
name in the prompt-bar settings (coming — for now edit the `llm_model` field in
the browser dev tools or change the default in `dlp_api_server.py`
`CommandParseRequest`).

### 3. Confirm it works

In a terminal:

```
ollama list            # shows models you've pulled
curl http://127.0.0.1:11434/api/tags   # should return JSON, not error
```

### 4. Enable it in the app

1. Reload the assessment tool at `http://localhost:8000` (Ctrl+F5)
2. Check the **"Use local LLM (Ollama)"** box under the prompt bar
3. Type a natural query — *"is my cloud firewall properly configured"*
4. The result banner will show an **LLM** tag if Ollama answered, or fall back
   to the deterministic parser with a note if Ollama is unreachable.

---

## Security notes

- **Loopback-only enforcement.** The app refuses any `llm_endpoint` that isn't
  `localhost` / `127.0.0.1` / `::1`. You cannot accidentally (or deliberately)
  point it at a cloud LLM from the GUI.
- **No credentials in prompts.** The text prompt is the only thing sent to the
  LLM. Tenant `client_id`, `client_secret`, `vanity_domain`, downloaded rule
  contents, or assessment results are never included.
- **Schema-constrained output.** The LLM is asked for JSON matching the
  command catalog. Any action or scope value outside the allowlist is
  rejected and the deterministic parser takes over.
- **Graceful fallback.** If Ollama is not running, unreachable, returns malformed
  JSON, or picks an invalid action, the tool transparently uses the
  deterministic parser. You'll see the reason in the `suggestion` field.
- **CSP still enforced.** The app's `Content-Security-Policy` header allows
  `connect-src 'self'` only. The LLM call is routed through the FastAPI server
  (same-origin), which forwards to loopback:11434 server-side — the browser never
  fetches from :11434 directly.

## Alternative local runtimes

Anything speaking the Ollama API or OpenAI-compatible chat API on loopback works.
Change the prompt-bar settings:

| Runtime | Endpoint | `llm_kind` |
| --- | --- | --- |
| Ollama          | `http://localhost:11434/api/chat`              | `ollama` |
| llama.cpp server| `http://localhost:8080/v1/chat/completions`    | `openai` |
| LM Studio       | `http://localhost:1234/v1/chat/completions`    | `openai` |
| vLLM            | `http://localhost:8000/v1/chat/completions`    | `openai` |

## Turning it off

Uncheck the **"Use local LLM"** box. The preference is stored in the browser's
`localStorage` under `zassess_use_llm`. Clear it to reset.

## Uninstall Ollama

| OS | Steps |
| --- | --- |
| Windows | Add/Remove Programs → Ollama → Uninstall |
| macOS   | Drag Ollama.app to Trash, then `rm -rf ~/.ollama` to delete downloaded models |
| Linux   | `sudo systemctl stop ollama && sudo rm /usr/local/bin/ollama && rm -rf ~/.ollama` |
