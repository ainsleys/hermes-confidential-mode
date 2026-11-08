# Tool classes by data flow

While a profile is locked, the tool gate runs a built-in tool without a prompt only when the tool's own code
sends the tool's data nowhere off this machine. This file holds every built-in tool Hermes registers at
commit 84a0301, the class the plugin gives it, and the evidence in Hermes' source. The code reads the same
table from `gate_tools_classify.py:BUILTIN_TOOL_CLASSES`;
`tests/unit/test_gate_tools.py::test_the_docs_table_equals_the_code_table` checks the two agree, and
`tests/seam/test_gate_tools_seam.py::test_every_builtin_tool_registered_at_the_pinned_hermes_has_a_data_flow_row`
checks every registered built-in has a row.

## The rule

- **on-host**: the tool's own code makes no network call and launches nothing that does. Local files, local
  SQLite, the Desktop app's channel between the user's app and the agent's host, and environment reads are
  on-host. A tool whose only network path installs a declared dependency from a package index (a package
  name, no session data) is on-host, with the install named in its evidence. The tool runs without a prompt
  while locked.
- **off-host**: data from the call's arguments or from this machine leaves it through the tool's own code
  (an HTTP request, a message to a chat platform, a page a browser the tool drives loads or receives text
  from, a model call), or the tool hands the data to another agent (a kanban task the gateway dispatcher
  gives to a worker of another profile), or launches a process or a pane that does so with the call's data.
  The tool asks before it runs.
- **unsettled**: the data flow cannot be settled from Hermes' source (a backend chosen by configuration that
  may be local or remote, a binary or plugin outside the tree, a command another program's configuration
  can choose). The tool asks before it runs.

Shell, code execution and the file tools keep the on-host class of the original contract: they run what the
model writes and are not inspected, and the preflight refuses to lock unless `terminal.backend` is `local`.
The `memory` tool is on-host because the preflight refuses to lock unless `memory.provider` is the built-in
store (`preflight.py:676-678`). `cronjob_manage` and `delegate_task` keep their own routes (blocked, and
checked per call); their class is recorded for completeness. A built-in tool the table does not name asks,
and the lock reply marks it "not audited".

Paths are under the Hermes checkout at 84a0301. "No network path" means the handler and every helper it
calls were read and none of them reaches the network. Two paths outside every handler are not part of a
tool's class: Hermes' opt-in shared metrics (`telemetry.shared_metrics.enabled`, off by default,
`hermes_cli/observability/relay_shared_metrics.py:1365-1376`) and the smart approval mode
(`approvals.mode: smart`, `tools/approval_smart.py:88-123`), which sends flagged commands to an auxiliary
model; the preflight classifies the auxiliary routes.

The kanban board is shared across profiles (`hermes_cli/kanban_db_connect.py:715-722`), and the gateway runs
the dispatcher by default (`hermes_cli/config_defaults.py:1879`, `dispatch_in_gateway: True`). The
dispatcher spawns `hermes -p <assignee> chat -q` for a ready task (`hermes_cli/kanban_db_dispatch.py:2755-2808`)
and `build_worker_context` (`hermes_cli/kanban_db.py:3896`) puts the task's title, body, comments and
attachments into that worker's system prompt. A worker of another profile is not under this lock and sends
to whatever provider its profile names, so every kanban tool that writes the board is off-host; the three
that only read it are on-host.

## The table

| Tool | Class | Evidence |
|---|---|---|
| `terminal` | on-host | Runs the command on the terminal backend (`tools/terminal_tool.py:1674`, `:1472-1599`); no HTTP library in `terminal_tool*.py` or `tools/environments/local.py`. Backend: `terminal.backend` (`hermes_cli/config.py:2015`, `tools/terminal_tool_backends.py:269`); the preflight requires `local`. |
| `process_manage` | on-host | Works on the in-memory process registry (`tools/process_registry.py:2711-2743`); non-local sessions read logs through the same backend (`:1427`, `:1460`). No HTTP library in `process_registry*.py`. |
| `execute_code` | on-host | Local: a child kernel over a 0600 Unix socket (`tools/code_kernel.py:524-541`); non-local backend: `_execute_remote` (`tools/code_execution_tool.py:787-788`). A script may call `web_search` or `web_extract` through the tool bridge (`:43-45`), each of which asks on its own. |
| `read_file` | on-host | Reads through the terminal backend (`tools/file_tools.py:312-371`). Office and PDF files load `anydoc` through `pm.ensure_import` (`tools/read_extract.py:81`), a package install when `security.allow_lazy_installs` is on; the file's bytes stay local. Class kept per the contract. |
| `write_file` | on-host | Writes through the terminal backend (`tools/file_tools.py:1321-1347`, `:902`). Post-write diagnostics may auto-install a language server (`agent/lsp/manager.py:218`, `install.py:144-176`); the file's bytes stay local. Class kept per the contract. |
| `patch` | on-host | `patch_tool` through the terminal backend (`tools/file_tools.py:1358-1369`, `:991`); same diagnostics note as `write_file`. |
| `search_files` | on-host | `rg` or `grep` on the terminal backend (`tools/file_tools.py:1372-1386`, `:1102`); the bundled ripgrep is looked up, never installed (`tools/file_operations_search.py:122-131`). |
| `skills_list` | on-host | No network path: scans local `SKILL.md` files (`tools/skills_tool.py:229-317`). |
| `skill_view` | on-host | No network path for the skill's text: it reads the local `SKILL.md` (`tools/skills_tool.py:613-735`). A skill whose frontmatter lists `deps:` runs `pm.ensure(dep)` (`:676-685`), a package install from the package index (`pm/downloader.py:64`, `:299`) when `security.allow_lazy_installs` is on (`hermes_cli/config_defaults.py:1780`); the install sends package names, no session data. |
| `skill_manage` | on-host | No network path: create, edit, patch, delete, write_file, remove_file on local skill files (`tools/skill_manager_tool.py:823-824`, `tools/skill_manager_batch.py:15`); `skills_guard.py` is regex scanning. |
| `todo_list` | on-host | No network path: an in-memory `TodoStore` on the agent (`tools/todo_tool.py:26-30`, `:201-219`). |
| `memory` | on-host | The built-in store writes local files (`tools/memory_tool.py:222-300`, `:400-477`). A write is mirrored to `memory.provider` (`agent/inline_tool_executors.py:152-161`, `agent/memory_manager.py:749-761`), and the preflight refuses to lock unless that provider is the built-in store (plugin `preflight.py:676-678`). |
| `clarify` | on-host | No network path of its own: the questions go to the surface's callback (`tools/clarify_tool.py:221`); in a gateway session that is the conversation's own channel to the user (`gateway/run_turn_runner.py:518`, `:646-675`). |
| `session_search` | on-host | No network path, no model or embedding call: SQLite FTS over the local `state.db`, read-only (`tools/session_search_tool.py:603-652`). |
| `annotate_preview` | off-host | The label travels to the Desktop app (`tools/annotate_preview_tool.py:38`), which runs it inside the previewed page with `webview.executeJavaScript`: `buildPinScript` passes the label to `w.__hermesWatch_fn(document, holder, stage, label)` on the page's `window` (`apps/desktop/src/app/chat/right-rail/preview-act.ts:128-141`, `:230-239`). The page's own scripts run in the same world and can read it, so the text reaches the page's remote origin. |
| `close_terminal` | on-host | No network path: `request_close_terminal` emits a `terminal.close` frame (`tools/process_registry.py:2327-2343`, `tui_gateway/session_notifications.py:858`). |
| `desktop_preview` | off-host | `open` sends `preview.open {url}` (`tools/open_preview_tool.py:84-89`; bare domains become `https://`, `:29-30`) and the Desktop webview loads the URL from its server (`apps/desktop/electron/preview-url-target.ts:17-40`). `read` and `close` are local. |
| `drive_preview` | off-host | Clicks, typing, submit and navigation on the loaded page (`tools/drive_preview_tool.py:53`; `apps/desktop/src/lib/preview-act/act-in-page.ts:547`, `:597-621`): typed text reaches the page's remote origin. |
| `focus_pane` | on-host | No network path: emits `pane.reveal {pane}` (`tools/focus_pane_tool.py:19-21`). |
| `gui_tour` | off-host | With `surface="preview"` (`tools/tour_tool.py:18`) the title, text and steps are passed as a JSON literal to a tour engine the Desktop installs in the previewed page with `webview.executeJavaScript`, and only when the page has not already defined `window.__hermesTourEngine` (`apps/desktop/src/app/chat/right-rail/preview-tour.ts:31-43`); a page that predefines it receives every string. The `app` surface draws in the app's own DOM (`apps/desktop/src/app/chat/tour-marker.ts`). |
| `react_to_message` | on-host | No network path: local SQLite through `hermes_state_registry.acquire()` (`tools/react_to_message_tool.py:18-19`, `:46`), then a `message.reaction` frame (`:54`). |
| `read_terminal` | on-host | No network path: the `terminal.read` callback, answered from the Desktop's terminal buffer (`tools/read_terminal_tool.py:16-32`). |
| `read_window_below` | on-host | No network path: the `window.read` callback, native window enumeration in the Electron main process (`tools/read_window_tool.py:15-23`). |
| `set_theme` | on-host | No network path: `{accent, mode, layout}` or `{picker}` to `theme_callback` (`tools/set_theme_tool.py:47`, `:55`). |
| `show_tip` | on-host | No network path: emits `tip.show` (`tools/tip_tool.py:28`). |
| `desktop_project` | unsettled | `hermes_cli/projects_db.py` is sqlite3 only (`:9-20`). The workspace callback runs `git -C <path> branch --show-current` and `rev-parse` on a model-chosen path (`tui_gateway/git_probe.py:34`, `:38`, `tui_gateway/agent_callbacks.py:194-221`) with no `-c` overrides, so a repository configuration there (`core.fsmonitor`, for example) can make git run a command the plugin cannot see from Hermes' source. |
| `computer_use` | unsettled | The backend is a plugin chosen by `computer_use.backend` (`plugins/computer_use/__init__.py:98-101`, `tools/computer_use/tool.py:159-161`); the built-in one starts a local `cua-driver` subprocess (`cua_backend_daemon.py:177`) whose binary is outside the tree, and it types into whichever desktop app it drives. |
| `setup_beat` | off-host | Toolset `onboarding` (`tools/setup_beat_tool.py:209`). `_connected()` calls `ConnectorClient().list_connectors()` (`:28-30`), an HTTP request to the connector gateway (`tools/connectors/gateway/client.py:96-101`, `:403-420`). |
| `kanban_attach` | off-host | Writes an attachment to the board through `_board()`, a local SQLite file (`tools/kanban_tools.py:312-326`, handler `:987`); `build_worker_context` lists attachments for the next worker (`hermes_cli/kanban_db.py:3896-3899`), so the attachment reaches the assignee profile's worker. |
| `kanban_attach_url` | off-host | `httpx.stream("GET", url, ...)` with the model-supplied URL (`tools/kanban_tools.py:1023`; SSRF check `:1018`). |
| `kanban_attachments` | on-host | No network path: reads attachments from local SQLite through `_board()` (`tools/kanban_tools.py:312-326`); handler `:1065`. |
| `kanban_block` | off-host | Writes the blocked status and the model's reason to the board (`tools/kanban_tools.py:812-850`); the reason is part of the task record `build_worker_context` reads and the notifier reports. |
| `kanban_comment` | off-host | Writes a comment the next worker receives in its system prompt (`tools/kanban_tools.py:964-971`: "comments are injected into future workers' system prompts"; `hermes_cli/kanban_db.py:3896`). |
| `kanban_complete` | off-host | Moves the task to done, which makes dependents ready for the dispatcher (`tools/kanban_tools.py:725`); for a `goal_mode` task `_goal_gate` (`:486-528`) first calls `judge_goal` (`hermes_cli/goals.py:918-946`, `call_llm`), sending the task title, body and summary to the `auxiliary.goal_judge` model (`agent/auxiliary_client.py:5402-5408`). |
| `kanban_create` | off-host | Writes a task with a model-chosen `title`, `body`, `assignee` (any installed profile) and `model` or `provider` override, status `running` by default (`tools/kanban_tools.py:1094-1155`); the dispatcher spawns the assignee profile's worker with that text (`hermes_cli/kanban_db_dispatch.py:2755-2808`). A notify subscription (`:1229-1258`) is delivered by the gateway. |
| `kanban_heartbeat` | on-host | No network path: updates the running task's heartbeat time, extends its claim and appends a `heartbeat` event carrying the model-supplied `note` in local SQLite through `_board()` (`tools/kanban_tools.py:312-326`; `hermes_cli/kanban_db_dispatch.py:605-640`); handler `:933`. The note is not added to any worker's context (`build_worker_context` reads comments and attachments only). |
| `kanban_link` | off-host | Writes a dependency between tasks (`tools/kanban_tools.py:1275`), which changes what `recompute_ready` promotes for the dispatcher. |
| `kanban_list` | off-host | Reads task summaries, but first calls `kb.recompute_ready(conn)` (`tools/kanban_tools.py:709`), which promotes tasks whose dependencies cleared to ready, where the dispatcher spawns their workers. |
| `kanban_request_changes` | off-host | Returns the task to its implementer with the model's reason and status `ready` (`tools/kanban_tools.py:920-930`), so the dispatcher respawns the implementer's worker with the reason in its context. |
| `kanban_request_review` | off-host | Moves the task to review (`tools/kanban_tools.py:873-916`) for a reviewer worker the dispatcher spawns; for a `goal_mode` task the same goal gate as `kanban_complete` (`:486-528`) sends the task text to the `auxiliary.goal_judge` model. |
| `kanban_schedule` | off-host | Writes a scheduled time to the task (`tools/kanban_tools.py:853`); the dispatcher spawns the worker when it comes due. |
| `kanban_show` | on-host | No network path: reads one task from local SQLite through `_board()` (`tools/kanban_tools.py:312-326`); handler `:663`. |
| `kanban_unblock` | off-host | Moves a blocked task to ready (`tools/kanban_tools.py:1260`), where the dispatcher spawns its worker. |
| `browser_cdp` | off-host | `websockets.connect(ws_url, ...)` (`tools/browser_cdp_tool.py:282`) sends CDP methods, `Page.navigate` and `Runtime.evaluate` among them (`:28`), to the endpoint from `get_cdp_override()` (`:127-130`), which may be a remote `wss://` URL; a navigation sends the URL to its site. |
| `browser_dialog` | off-host | `Page.handleJavaScriptDialog {accept, promptText}` (`tools/browser_supervisor_dialogs.py:246`) over the supervisor's CDP WebSocket (`tools/browser_supervisor.py:381`): the prompt text reaches the page that opened the dialog. |
| `browser_exec` | off-host | `subprocess.Popen` of `browser_harness.run` with the model's code (`tools/browser_use_cli.py:600`, `:272`), which navigates to model-supplied URLs (`:940-949`) on the backend picked at `:399-478` (`browser.cloud_provider`; a cloud session is created with `requests.post`, `plugins/browser/_common.py:92`). |
| `browser_vault` | off-host | `fill` and `enter_code` write the decrypted credential into the live page through `supervisor.evaluate_runtime` (`tools/browser_vault_tool.py:171`, from `:436` and `:580`), bound to the item's origin (`:238-262`); the site receives it on submit. |
| `web_search` | off-host | `provider.search(query, fetch_limit)` (`tools/web_tools.py:360`), the provider from `web.backend` (`:100-190`), for example Tavily `httpx.post` (`plugins/web/tavily/provider.py:47`); every provider sends the query to a search service. |
| `web_extract` | off-host | `provider.extract(fetch_urls, ...)` (`tools/web_tools_extract.py:168`), the provider from `web.extract_backend` (`tools/web_tools.py:187`), for example Firecrawl `httpx.post` (`plugins/web/firecrawl/provider.py:120`). |
| `x_search` | off-host | `requests.post(f"{base_url}/responses", ...)` with the query and handles (`tools/x_search_tool.py:171`, `:251`). |
| `image_generate` | off-host | Dispatch at `tools/image_generation_tool.py:834-840`; FAL `fal_client.submit(model, arguments=...)` (`:128`) sends the prompt and source images; the bundled providers (deepinfra, fal, krea, meta-ai, openai, openrouter, xai) are all hosted. |
| `vision_analyze` | off-host | A URL image is downloaded (`tools/vision_tools.py:275-279`); the image goes to the main model's next request (`:1018-1020`) or to `async_call_llm(task="vision")` (`:825`, `:913`), a model call. |
| `video_analyze` | off-host | `_download_media` for URL videos (`tools/vision_tools.py:1115`); the video goes to `async_call_llm` through `_call_vision_llm` (`:1143`, `:771`), a model call. |
| `video_generate` | off-host | `provider.generate(prompt=prompt, **kwargs)` (`tools/video_generation_tool.py:204`), for example xAI `client.post(f"{base_url}/videos/{endpoint}", ...)` (`plugins/video_gen/xai/__init__.py:273`). |
| `xai_video_edit` | off-host | `run_xai_video_edit` (`plugins/video_gen/xai/__init__.py:181`) posts the prompt and video to `{base_url}/videos/{endpoint}` (`:273`). |
| `xai_video_extend` | off-host | `run_xai_video_extend` (`plugins/video_gen/xai/__init__.py:186`) posts to the same endpoint (`:273`). |
| `text_to_speech` | unsettled | `tts.provider` picks the engine (`tools/tts_tool.py:105`, `:148`): the default `edge` and the other hosted providers send the text (`tools/tts_tool_providers.py:203`, `:155`); `neutts`, `piper` and `kittentts` run locally (`tools/tts_tool_local.py:61`, `:141`, `:187`) but may fetch a voice or model on first use; a command provider runs the configured command (`tools/tts_command_provider.py:183`). |
| `discord` | off-host | `urllib.request.urlopen(req)` to `https://discord.com/api/v10` (`tools/discord_tool.py:68`, `:26`). |
| `discord_admin` | off-host | The same `_discord_request` (`tools/discord_tool.py:68`) with the admin actions (`:618-620`). |
| `feishu_doc_read` | off-host | `client.request(request)` GET `/open-apis/docx/v1/documents/:id/raw_content` (`tools/feishu_doc_tool.py:49`). |
| `feishu_drive_add_comment` | off-host | `client.request(...)` POST `/open-apis/drive/v1/files/:token/new_comments` with the comment text (`tools/feishu_lark.py:62`, `tools/feishu_drive_tool.py:177-181`). |
| `feishu_drive_list_comment_replies` | off-host | GET `.../comments/:id/replies` (`tools/feishu_lark.py:62`, `tools/feishu_drive_tool.py:168-170`). |
| `feishu_drive_list_comments` | off-host | GET `/open-apis/drive/v1/files/:token/comments` (`tools/feishu_lark.py:62`, `tools/feishu_drive_tool.py:165-167`). |
| `feishu_drive_reply_comment` | off-host | POST `.../replies` with the reply text (`tools/feishu_lark.py:62`, `tools/feishu_drive_tool.py:172-176`). |
| `yb_query_group_info` | off-host | `_ws_query` sends over the Yuanbao WebSocket (`plugins/platforms/yuanbao/adapter.py:2094`, connected at `:1840` to `wss://bot-wss.yuanbao.tencent.com`). |
| `yb_query_group_members` | off-host | `get_group_member_list` through `_ws_query` (`plugins/platforms/yuanbao/adapter.py:2763`, `:2094`). |
| `yb_search_sticker` | on-host | No network path: a fuzzy match over the in-memory sticker table (`tools/yuanbao_tools.py:163-178`, `plugins/platforms/yuanbao/yuanbao_sticker.py:175`, `:20`). |
| `yb_send_dm` | off-host | `adapter.send_dm` and `send_media` over the Yuanbao WebSocket (`plugins/platforms/yuanbao/adapter.py:2791-2815`). |
| `yb_send_sticker` | off-host | `_outbound.sender.send_media(chat_id, "sticker", ...)` (`plugins/platforms/yuanbao/adapter.py:2808-2810`). |
| `manage_catalog` | unsettled | Through the registry handler it returns before any I/O (`tools/connectors/tool.py:175`, `tools/connectors/catalog_tool.py:113-114`); through the agent's inline executor (`agent/inline_tool_executors.py:218-226`) `search` fetches the live catalog (`hermes_cli/plugin_catalog.py:35`, `:374`) and `install` clones the plugin (`hermes_cli/plugins_cmd_git.py:232`). Which path a locked call takes is not settled here. |
| `manage_connections` | off-host | `ConnectorClient` requests to the connector gateway (`tools/connectors/managed.py:64`, `:93`, `:114`; `tools/connectors/gateway/client.py:394`); `install` connects to the catalog's MCP server (`tools/connectors/mcp.py:180`, `hermes_cli/mcp_config.py:459`). |
| `cronjob_manage` | off-host | Route: blocked. `run` executes the job's agent in this process (`tools/cronjob_tools.py:335`, `:382`), a model call; with `cron.provider: chronos` every change is sent to the portal (`plugins/cron_providers/chronos/_nas_client.py:44-56`). Create, list, update and remove write `cron/jobs.json` (`cron/jobs.py:95`). |
| `delegate_task` | off-host | Route: checked per call. Child agents run in this process (`tools/delegate_tool.py:238`, `:293-308`) and each calls a model provider chosen by `delegation.backend` and `delegation.provider` (`agent/delegation_registry.py:128-134`, `tools/delegate_tool_config.py:478-497`). |

## Counts

73 tools: 25 on-host, 44 off-host, 4 unsettled. Of the 48 that are not on-host, `cronjob_manage` is blocked
and `delegate_task` is checked per call; the other 46 ask the first time they run in a conversation during a
lock.
