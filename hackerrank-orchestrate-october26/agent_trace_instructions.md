# Agent Trace Instructions

Please submit the complete agent trace for the work you did on this challenge as a **ZIP file**. A trace helps us understand the prompts, model responses, tool calls, and work performed during the session and improve our evaluation from the next time.

Include every session you used for this challenge, including sessions in which you planned, coded, debugged, or reviewed the solution. If you used more than one agent harness, include traces from each one. Keep the original files and folder structure where practical; do not convert JSONL, SQLite, or other structured logs into screenshots or summaries.

## Before you start

1. Finish the session(s) you intend to submit, then quit the app or CLI before copying its files. This helps ensure logs are written completely.
2. Create a temporary folder named `agent-trace` somewhere easy to find, such as your Desktop. Copy only the relevant trace files into it. Keep each tool in its own subfolder, for example `agent-trace/claude-code/` and `agent-trace/codex/`.
3. Include the session files for this challenge, not your entire home directory or application-data folder.
4. Review the staged files before sharing. Traces can contain source code, local file paths, prompts, tool arguments and output, screenshots, and other private information. Remove or redact secrets (API keys, tokens, passwords, cookies, private keys), personal information, and material you are not allowed to share. Do not include authentication files, settings, or credentials.
5. Zip the `agent-trace` folder using your operating system’s built-in archive tool. Name the result `agent-trace.zip`.

## Claude Code

### Where traces are stored

Claude Code stores session transcripts by project under:

- **macOS/Linux:** `~/.claude/projects/`
- **Windows:** `%USERPROFILE%\.claude\projects\`

Each project folder contains session files, commonly JSONL files named with a session ID. Find the folder corresponding to your challenge checkout and copy the session files you created for this challenge into `agent-trace/claude-code/`. The folder name may encode the project path, so check the session content and timestamps to identify the right files.

### Export a readable transcript

In each Claude Code session, run:

```text
/export
```

Save the exported transcript in `agent-trace/claude-code/`. `/export` produces a readable conversation export; include the original session JSONL files as well when available because they preserve the structured trace.

If you used Claude in the Claude web app or desktop chat rather than Claude Code, that is a different product history: use **Settings → Privacy → Export data** and follow the download instructions. Include only the relevant conversation export.

## OpenAI Codex

### Where traces are stored

Codex CLI and local Codex app sessions commonly store structured rollout files under:

- **macOS/Linux:** `~/.codex/sessions/`
- **Windows:** `%USERPROFILE%\.codex\sessions\`

The files are organized into date folders and are typically named `rollout-*.jsonl`. If you set `CODEX_HOME`, look under `$CODEX_HOME/sessions/` instead. Copy the rollout JSONL files for the challenge sessions into `agent-trace/codex/`. You can use their timestamps and session IDs to identify them. Include a matching `session_index.jsonl` only if useful for mapping session IDs to titles; review it for unrelated information first.

Do **not** copy `auth.json`, `config.toml`, credential stores, or the whole `.codex` directory.

If you used Codex only in a hosted/cloud interface and there is no local rollout file, use the interface’s conversation export or share/download option if available. If no transcript download is available, submit the conversation transcript in the format the interface provides and note that it was a hosted session with no local trace file.

## Google Antigravity

Antigravity writes a `transcript.jsonl` for each conversation under that conversation’s `brain` folder. The transcript includes agent activity; the same folder can also contain artifacts and screenshots associated with the conversation. Preserve the full relevant conversation folder when you need its artifacts to understand the trace.

Typical locations:

- **Antigravity app:** `~/.gemini/antigravity/brain/<conversation-id>/`
- **Antigravity CLI:** `~/.gemini/antigravity-cli/brain/<conversation-id>/`
- **Antigravity IDE:** `~/.gemini/antigravity-ide/brain/<conversation-id>/`
- **Windows:** look under `%USERPROFILE%\.gemini\antigravity\brain\`, `%USERPROFILE%\.gemini\antigravity-cli\brain\`, or `%USERPROFILE%\.gemini\antigravity-ide\brain\`, depending on the product used.

Within the relevant conversation folder, the transcript is at:

```text
.system_generated/logs/transcript.jsonl
```

Copy the complete `<conversation-id>` folder(s) for this challenge to `agent-trace/antigravity/`. Do not copy the entire `.gemini` directory: it may contain unrelated data. Antigravity CLI’s `last_conversations.json` is a session lookup cache, not the transcript itself.

## OpenCode

OpenCode stores session and message data in a local SQLite database. Its default application-data directory is:

- **macOS/Linux:** `~/.local/share/opencode/`
- **Windows:** `%USERPROFILE%\.local\share\opencode\`

The database is usually `opencode.db`. To find its active path (including custom XDG or `OPENCODE_DB` locations), run:

```sh
opencode db path
```

Prefer exporting each relevant session as JSON rather than copying the database. List sessions and export each challenge session:

```sh
opencode session list --format json
opencode session export <session-id> > <session-id>.json
```

To redact sensitive transcript and file data during export, add `--sanitize`:

```sh
opencode session export <session-id> --sanitize > <session-id>.json
```

Place the exported files in `agent-trace/opencode/`. If the CLI is unavailable and you need to provide the raw database instead, quit OpenCode first, copy only `opencode.db` into the staging folder, and inspect the copy for unrelated/private data. Never include `auth.json`, which can contain provider credentials. The default OpenCode data folder also contains logs and snapshots; those are not substitutes for the session exports.

## Other Harnesses

If you used an agent harness or coding tool that is not listed above (for example, Aider, Goose, RooCode, Cline, Devin, Factory, or JetBrains Junie):

1. **Finish and quit the session** so all logs and session files are completely written to disk.
2. **Create a tool subfolder** inside `agent-trace/` named after the harness (for example, `agent-trace/cursor/`, `agent-trace/windsurf/`, `agent-trace/copilot/`, `agent-trace/aider/`, or `agent-trace/goose/`).
3. **Export and copy the session traces for this challenge:**
   - Use the tool’s built-in session, chat, or trajectory export feature (UI or CLI) to save a readable or structured export into `agent-trace/<harness-name>/`.
   - Copy the raw structured trace files for this challenge from the tool’s local storage directory (such as `.jsonl`, `.json`, `.db`, or chat history files) into `agent-trace/<harness-name>/`, preserving original file formats and any subagent folders. Include only the sessions from this challenge.
4. **Redact secrets and exclude credentials:** Remove or redact any API keys, tokens, passwords, cookies, private keys, or personal data. Do **not** include authentication files, settings, or credential stores (such as `auth.json`, `config.json`, `mcp.json`, `mcp_config.json`, or `.env`).
5. **Package and upload:** Follow the steps below to create `agent-trace.zip` and upload it with your challenge submission.

## Create the ZIP

### macOS or Linux

From the directory containing `agent-trace/`:

```sh
zip -r agent-trace.zip agent-trace
```

### Windows PowerShell

From the directory containing `agent-trace/`:

```powershell
Compress-Archive -Path .\agent-trace -DestinationPath .\agent-trace.zip -Force
```

Open the ZIP once after creating it and confirm it contains the intended traces and no credentials or unrelated files. Submit `agent-trace.zip` with your challenge submission.
