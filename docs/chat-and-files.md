# Talking to the agent and reaching its workspace

Until now a sandbox was a batch machine: you queued a task, the harness ran it to the end,
and you read the result. This document describes the conversation model that replaces it,
how it is built, and the workspace file access that comes with it (tree, read, upload).

## What you can do

```sh
sandboxctl chat sb_1234                       # replay the conversation, then talk
> add integration tests for the checkout flow
17:02:11   ⚙ Read
17:02:14 agent: I read the checkout module; adding tests under tests/checkout/.
> /attach ./spec/checkout.md                  # uploaded to /workspace/uploads/checkout.md and announced
> use the acceptance criteria from the attached spec
17:03:40 agent: Updated the tests to follow the spec's five criteria.
> /files repo/tests                           # the workspace, one level
> /close                                      # ends the open conversation; the run finishes
> /quit

sandboxctl messages sb_1234                   # the conversation so far
sandboxctl files sb_1234 repo -depth 2        # tree
sandboxctl cat sb_1234 repo/tests/checkout_test.py
sandboxctl put sb_1234 ./fixtures.json uploads/fixtures.json
```

Over the API the same is `POST /v1/sandboxes/{id}/messages` (JSON `{text, attachments}` or
multipart with `text` and `file` parts), `GET /v1/sandboxes/{id}/messages` (one page, `?after=`),
`GET /v1/sandboxes/{id}/messages/stream` (SSE: replay, then live), `POST .../messages/close`,
`GET /v1/sandboxes/{id}/files?path=&depth=`, `GET`/`PUT /v1/sandboxes/{id}/files/content?path=`.

## The conversation model

A sandbox's conversation is a chain of runs that share one harness session. The main path is an
ACP harness (`input: acp`, [below](#acp-harnesses)): one protocol for every agent, through which
the runner sets the mode, the model and the system prompt, records diffs and permission
decisions, counts usage per turn and continues the session in the next run. `text` and
`stream-json` remain for harnesses that do not speak ACP. Three things make the conversation
continuous:

Choosing the run that carries a message and recording it happen under one lock per sandbox
shared by every replica (an advisory lock in PostgreSQL), so two messages sent at the same
moment join the same conversation instead of starting two.

1. **A message reaches a run in progress as input — in stream-json mode.** `POST /messages` on a
   sandbox whose run is running (or queued) appends an `input` event; the runner hands it to the
   harness's stdin. That needs a harness started in streaming-input mode:

   ```yaml
   harness:
     command: 'claude -p --input-format stream-json --output-format stream-json --verbose --permission-mode bypassPermissions --permission-prompts none'
     input: stream-json      # one JSON user message per line; the conversation stays open
     chat_idle: 600          # seconds without a new message after a turn before it is closed
   ```

   In `stream-json` mode the runner sends the task as the first user message and every later
   message as another one, so the harness keeps its context and answers each in the same
   process. The delivery is reported as `input`.

   A `text`-mode harness (the default) gets its task on stdin and then EOF: `claude -p` reads a
   non-terminal stdin to its end before it starts. Its messages never become `input` events. A
   message for a run that is still queued joins that run's task (reported as `input`; the task
   is what the harness reads), and one sent while the run is executing is queued as the next run
   (`resumed`, `resume_of` the running run): it starts when that run finishes and continues the
   session it reported. `POST /runs/{run}/input` on a text-mode sandbox is refused with 409.

2. **Between runs the session is resumed.** When no run is active, `POST /messages` queues a new
   run with `mode: message`, `resume_of` the latest run of the session and the message as the
   task. The runner executes the profile's `resume_command` with `$SANDBOX_SESSION` (the id the
   control plane captured from the harness output: Claude Code's `session_id`, Codex's
   `thread_id`) and the message in `$SANDBOX_RESUME_PROMPT`:

   ```yaml
   harness:
     resume_command: 'claude -p "$SANDBOX_RESUME_PROMPT" --resume "$SANDBOX_SESSION" --output-format stream-json --verbose --permission-mode bypassPermissions --permission-prompts none'
   ```

   The delivery is reported as `resumed`. With no session to continue (a sandbox that never
   ran, or whose harness never reported a session) the message starts a fresh conversation
   (`new`). This path works with any harness, including plain `claude -p` and `codex exec`.

3. **An open conversation ends cleanly.** `POST /messages/close` (or `/runs/{run}/close`) sends a
   `run.close` control event; the runner closes the harness's stdin, the harness exits, the run
   finishes with its exit code and usage. In `stream-json` mode the runner also closes the
   conversation by itself after `chat_idle` seconds without a message following a completed turn
   (default 10 minutes), so an idle chat does not hold a pod and a run open forever. The next
   message resumes the session (point 2). Cancelling a run (`/cancel`) stops the harness: SIGINT
   first (`claude -p` completes its turn and writes its result on it), SIGTERM 5 seconds later if it
   is still running.

   `claude -p` runs with `--permission-mode bypassPermissions --permission-prompts none` in the
   shipped commands: since Claude Code 2.1.302 `-p` starts in a manual mode that refuses every
   edit and non-read-only command nobody approves, and in a pod nobody does. The sandbox is the
   boundary; for recorded per-request decisions use ACP. Its MCP configuration names the servers
   by their gateway bridge URLs. `codex exec --json` gets its usage counted from each
   `turn.completed` (`examples/catalog/environment-codex-chatgpt.yaml` has the flags it needs in a pod).

Forced rollouts keep working on the same mechanism: the interrupted run is re-queued with
`mode: resume` and the harness is told to continue where it left off.

### ACP harnesses

`input: acp` makes the profile's command an [Agent Client Protocol](https://agentclientprotocol.com)
agent and agent-runner its client, over the agent's stdio (JSON-RPC). The image carries the
adapters for both vendors and OpenCode, pinned in `hack/ci/versions.env`:

```yaml
harness:
  command: claude-agent-acp        # or codex-acp, opencode acp, any agent that speaks ACP (gemini --experimental-acp…)
  input: acp
  permissions: allow               # allow (default) | deny
  mode: default                    # optional: the session mode (claude-agent-acp default, codex-acp agent-full-access, OpenCode build)
  mcp: auto                        # auto (default) | always
  auth_method: api-key             # optional: the agent's authentication method (ACP authenticate)
```

- **One session per conversation.** The run's task is the first `session/prompt` of a new
  session; every later message is the next prompt of the same session (a message sent while a
  turn runs waits for it to end). A run that continues the conversation (the next message after
  the run finished, a rollout) continues the session it reported: with `session/resume` when the
  agent declares it (`sessionCapabilities.resume`; nothing is replayed), else with
  `session/load` (the history the agent replays is not written again), else in a new session,
  which the runner reports. `resume_command` is not used.
- **Mode.** `mode` (`HARNESS_MODE`) is set right after the session opens, new or continued: through
  the agent's configuration option of category `mode` when it has one, else `session/set_mode`.
  The ids are the agent's own: claude-agent-acp `default` (its permission checks on, so requests
  reach the runner), codex-acp `agent-full-access` (its default `agent` mode needs Codex's
  bubblewrap sandbox, which does not start in a pod, and lets a reviewer model decide), OpenCode
  `build`. A mode the agent does not offer is reported with the ones it does; the agent keeps
  its own.
- **Model.** The profile's `model.name` (`SANDBOX_MODEL`) is selected through the agent's
  configuration option of category `model`: the same value, a provider-qualified one
  (OpenCode's `anthropic/claude-…`) or an option of that name. An agent without such an option,
  or without that model, is told nothing and the run says so; its own configuration decides
  (`ANTHROPIC_MODEL`, Codex's `model`).
- **Authentication.** An agent that refuses `session/new` with "Authentication required" names
  its methods in `initialize` (`authMethods`); `auth_method` makes the runner `authenticate`
  with one of them before the session (codex-acp: `api-key`, with the key in the environment).
  Without it the runner reports the methods the agent offers. An adapter may also take the
  choice from its own environment (codex-acp: `DEFAULT_AUTH_REQUEST`).
- **MCP servers** of the agent's connections go into `session/new` (and load, resume) as HTTP
  servers, by their gateway bridge URLs. With `mcp: auto` the agent must announce
  `mcpCapabilities.http`, otherwise they are left out with a notice; `mcp: always` passes them
  anyway, for an agent that takes them without saying so (Hermes).
- **Instructions.** An agent that declares the client system prompt
  (`sessionCapabilities.systemPrompt`, claude-agent-acp) gets the agent definition's
  instructions as one, appended to its own, in `session/new` and again in a load or resume (a
  system prompt is not part of the history): they survive the agent compacting its context. Any
  other agent gets them ahead of the task in a new session's first prompt, in an
  `<instructions>` block. (acp-go-sdk v0.13.5 has no field for it: the runner adds it at the
  JSON-RPC level, `cmd/agent-runner/acp_wire.go`.)
- **Permissions.** `session/request_permission` is answered by `permissions`: the agent's
  `allow_once` (else `allow_always`) option, or with `deny` its `reject_once` (else
  `reject_always`). The sandbox, its policy and the gateway stay the boundary either way. Every
  request and its decision is a line of the run's output, with the change's diff when the
  request carries one (OpenCode and Hermes send it nowhere else).
- **Messages.** A message that starts with `/` is sent with a zero-width space ahead of it, so
  the agent reads it as text and not as one of its slash commands (OpenCode ends the turn empty
  on an unknown one).
- **Output.** The runner writes what the agent reports as one JSON line each:

  | `type`            | fields                                                    | transcript |
  |-------------------|-----------------------------------------------------------|------------|
  | `acp.session`     | `session_id`                                              | — (the run's session) |
  | `acp.message`     | `text` (the agent's chunks of one message, joined)        | `assistant` |
  | `acp.tool_call`   | `tool_call_id`, `title`, `kind`, `status`, `diffs[]` (`path`, `change`, `old_path`, `old_text`, `new_text`, `old_size`, `new_size`, `truncated`), `diffs_replace` | `tool` |
  | `acp.tool_update` | `tool_call_id`, `status`, `diffs[]`, `diffs_replace`       | `log` |
  | `acp.permission`  | `tool_call_id`, `title`, `decision`, `diffs[]`, `diffs_replace` | `log` |
  | `acp.turn_end`    | `stop_reason`                                             | ends the turn (`chat_idle` counts from here) |

  **The diffs of a tool call are those of its last line that has any.** A line repeats no diff
  the call's previous line already carried; one with different diffs says `diffs_replace`
  (Claude sends a preview in the tool call and the real hunks in an update; a permission
  request's diff may be refined by the call's update). `change` is the kind of change when the
  agent says it (codex-acp: `add`, `update`, `delete`, `rename` with `old_path`). A diff whose
  texts exceed 128 KiB keeps its path and sizes and is marked `truncated` (the file is in the
  workspace). Changes an agent makes through its shell (`sed -i`, a generator) come with no diff
  from any agent. The agent's stderr is passed through as it is.
- **Usage.** Each turn ends with one `{"type":"usage",…}` line the run's accounting adds up,
  whatever the agent's own convention:

  | agent | reports | recorded |
  |---|---|---|
  | claude-agent-acp | the turn's tokens; `usage_update.cost`, the session's cost so far | the tokens; the cost by what it grew since the previous turn (work the agent did in the background between turns included) |
  | codex-acp | the turn's tokens, cached apart, reasoning inside the output | as reported |
  | OpenCode | the last model call of the turn only; `usage_update.cost` | the last call's tokens (a turn of several calls is undercounted: the agent reports no more); the cost's growth |
  | Hermes | the session's running total | the share since the previous turn, its last total kept on the workspace (`~/.sandbox-acp-usage/`) so the next run of the session continues from it |

  Reasoning tokens (`thoughtTokens`) are added to the output only when the agent counts them
  beside it (`totalTokens` includes them on top of input and output).
- **Lost turns (Hermes).** When Hermes's gateway restarts in the middle of a turn, the session
  refuses every prompt (`unknown_execution`) until the lost turn is discarded: the runner sends
  the `/discard <id>` the refusal names and the prompt once more.
- **Gateway bridge.** Every connection out of the pod ends at the gateway, which requires the
  pod's client certificate (mTLS). Claude Code, git and curl present it from what agent-init
  writes; most other harnesses cannot (OpenCode on Bun, Hermes on Python's httpx, Codex on Rust
  read no client certificate from the environment). agent-runner therefore serves a bridge on
  the pod's loopback, `http://127.0.0.1:4480/https/<host>/<path>` (`$SANDBOX_GATEWAY_BRIDGE`),
  that forwards to `https://<host>/<path>` through the gateway with the certificate: headers and
  bodies unchanged (the gateway still swaps placeholder credentials and applies the policy),
  answers streamed, WebSocket upgrades carried. A profile points its harness's provider at it
  (`ANTHROPIC_BASE_URL`, OpenCode's provider `baseURL`, Codex's `model_providers.<id>.base_url`;
  Codex ignores `OPENAI_BASE_URL`), and the MCP servers an ACP
  agent gets in `session/new` are already bridge URLs. It reaches nothing the pod could not:
  the certificate is the pod's own and the network lock still admits only the gateway.
- **OpenCode** (`command: opencode acp`, `examples/catalog/environment-opencode-acp.yaml`) is an
  ACP agent itself: it loads sessions (a conversation continues across runs), takes the MCP
  connections over HTTP and needs no `auth_method` with a provider key in its environment. Its
  configuration is `OPENCODE_CONFIG_CONTENT` and its permission rules `OPENCODE_PERMISSION`, which
  take precedence over an `opencode.json` in the repository (a harness file would not: a
  repository could point the provider past the bridge or lift the rules). With the rules at
  `ask`, every edit and shell command reaches `permissions` and the run's output; a `deny` profile
  sets them to `deny`, since OpenCode ends the whole turn on the first rejected request.
  `webfetch` and `websearch` are denied, and `autoupdate` off, `share` disabled,
  `OPENCODE_DISABLE_MODELS_FETCH`, `OPENCODE_DISABLE_LSP_DOWNLOAD` and
  `OPENCODE_DISABLE_CLAUDE_CODE` keep it from egress and configuration a pod has no use for.
  After an approved edit OpenCode tells the client through `fs/write_text_file` although the
  runner declares no file system: the runner answers success and writes nothing (the file is
  already on disk). Its Anthropic provider's `baseURL` is the gateway bridge: OpenCode cannot
  present the pod's client certificate itself.
- **Hermes Agent** (`command: hermes acp`, `examples/catalog/environment-hermes-acp.yaml`) runs
  from its own image, `agent-hermes`: the official Hermes image pinned by digest
  (`HERMES_IMAGE` in `hack/ci/versions.env`) with agent-init, agent-runner, the network lock and
  user 1000 added (`images/agent-hermes/Dockerfile`). Hermes ships as that image, not as a
  package the default agent image could install. The admin publishes it as a version of the
  agent catalogue (`agent.versions.hermes: …/agent-hermes:sha-…@sha256:…`) and the profile names
  `image: hermes`. `HERMES_HOME` is `~/.hermes` on the workspace volume (config, sessions,
  memory, skills survive restarts); its configuration is a harness file, `.hermes/config.yaml`:
  `approvals.mode: off` with `permissions: allow` (its default, `smart`, lets a model decide, so a
  deny profile would not be obeyed; a deny profile sets `manual`), the remote model catalogue,
  lazy installs and the web and browser toolsets off. Hermes takes MCP servers over HTTP without
  declaring it: the profile says `mcp: always`. Hermes's own login is interactive and not used:
  the provider key is a placeholder in `env`, and `ANTHROPIC_BASE_URL` (read from the environment
  only) is the gateway bridge (Hermes's httpx client cannot present the pod's client certificate).
- **Checked offline in CI.** `hack/ci/images.sh` runs the ACP smoke tests inside the built
  images with no network: the shipped Codex, OpenCode and Hermes profiles open a session with
  the real agent in the profile's mode (the agent must accept it), and OpenCode's and Hermes's
  are loaded again by a second process (the next run); claude-agent-acp must take the
  instructions as its system prompt and the profile's mode.
  Each also makes a real model call through the runner against a test gateway that requires the
  pod's client certificate: OpenCode's and Hermes's answers come back into the transcript,
  Codex's request arrives at `/v1/responses` with the certificate.
- **Long lines.** For every harness, an output line over 1 MiB is replaced by a
  `[agent-runner] dropped an output line …` notice and reading goes on, so the harness never
  blocks on a reader that gave up.
- **The runner offers no file system or terminal** to the agent (client capabilities are empty):
  the agent uses its own tools inside the pod, under the pod's network lock.

### The transcript

`GET /messages` derives the conversation from the sandbox's event stream, so it survives
restarts and replicas and needs no second store. Each turn is `{id, run_id, role, text, at}`:

| role        | source                                                                           |
|-------------|----------------------------------------------------------------------------------|
| `user`      | `run.queued` (the task or the message a run was created with), `input` events    |
| `assistant` | text blocks of Claude Code `assistant` lines; Codex `agent_message` items        |
| `tool`      | tool calls (`tool_use` blocks): the tool name                                    |
| `system`    | run boundaries: `run done` / `run failed` / `run cancelled`, a rollout resume    |
| `log`       | any other harness output line, only with `?raw=true`                             |

`id` is the event the turn came from; `?after=<id>` and the SSE `Last-Event-ID` continue from
there, and `X-Next-Cursor` on a page is the last event scanned (turns are a subset of events).

## Workspace files

The pod's workspace is a volume only the pod can see, so file operations are performed by
the runner on request. The control plane never execs into pods and the pod keeps its network
lock: everything travels over the existing mTLS agent API.

```
client ── GET /files?path=repo ──▶ sandboxd ── fs.request event ──▶ (event stream)
                                              ◀── fs.result event ──  agent-runner polls
                                                                       /agent/fs/requests,
                                                                       performs the operation,
                                                                       POST /agent/fs/results
```

- **list** returns entries (`path`, `type`, `size`, `mod_time`) below `path`, `depth` levels deep
  (1..8, at most 5000 entries, `truncated` when cut).
- **read** has the runner upload the file to a transfer blob (`POST /agent/blobs`, 16 MiB
  limit); the API streams it back with the detected content type and deletes the blob.
- **write** stores the body as a transfer blob first; the runner fetches it
  (`GET /agent/blobs/{name}`) and writes the file atomically, creating parent directories.
  `PUT /files/content` and message attachments (`uploads/<name>`) use it.

Paths are relative to `/workspace` (a leading `/workspace/` is accepted). Every operation is
performed through `os.Root` opened on the workspace: a path with a `..` segment is refused
outright, and a symlink that leaves the workspace, whether the file itself or any directory on
the way, including a parent that does not exist yet for a new file, is refused by the kernel-side
check at every step. Relative symlinks that stay inside the workspace work; absolute symlinks are
treated as relative to the workspace root (so a link to `/workspace/x` or to anything outside
does not resolve). Writing onto a symlink replaces the link with a regular file inside the
workspace and never touches its target. Transfer blob names are confined to the sandbox that
owns them (`fs/<sandbox>/…`): a pod can neither read another sandbox's upload nor answer another
sandbox's request, and uncollected blobs are purged after an hour.

Delivery is at-least-once in both directions. The runner moves its cursor past a request only
once its answer was acknowledged; an answer lost to a transient failure is retried with
backoff, and a request still unanswered is served again by the next poll (the control plane
lists every unanswered request of the last ten minutes, however long the answered history before
it). The gateway side resolves only the connections of the host being requested, so a secret
missing for one external service never blocks the agent's calls to the control plane or to
other services.

A file request on a sleeping sandbox wakes it (pass `?wake=false` to get 409 instead) and waits
up to three minutes for the pod; on a running sandbox the wait is one minute (504 on timeout).
Requests older than ten minutes are not served: whoever asked has stopped waiting.

## Design notes

- No new transport. Messages, control (`run.close`) and file operations are events in the
  sandbox's stream, which already fans out across replicas (PostgreSQL LISTEN/NOTIFY) and is
  already what the runner long-polls. A request works whichever replica the pod talks to.
- The transcript is a projection of the stream (`internal/harness` parses the turns), not a
  table: nothing to migrate or keep consistent, and the raw stream stays available.
- The harness decides what "continuity" means. The platform captures the session id, knows
  how to hand a message in (`input` mode) and how to resume (`resume_command`); the profile
  author picks the commands. Claude Code gets a live multi-turn conversation; a harness without
  streaming input still gets a continuous conversation through resume runs.
- Every file operation goes through the same access check as the sandbox itself (the tenant's
  token or the admin's) and leaves no copy of the content in the control plane once delivered.
