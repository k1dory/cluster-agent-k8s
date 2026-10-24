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

A sandbox's conversation is a chain of runs that share one harness session. Three things make
it continuous:

1. **A message reaches a run in progress as input.** `POST /messages` on a sandbox whose run is
   running (or queued) appends an `input` event; the runner hands it to the harness's stdin. For
   Claude Code that is useful only when the harness was started in streaming-input mode:

   ```yaml
   harness:
     command: 'claude -p --input-format stream-json --output-format stream-json --verbose'
     input: stream-json      # one JSON user message per line; the conversation stays open
     chat_idle: 600          # seconds without a new message after a turn before it is closed
   ```

   In `stream-json` mode the runner sends the task as the first user message and every later
   message as another one, so the harness keeps its context and answers each in the same
   process. The delivery is reported as `input`.

2. **Between runs the session is resumed.** When no run is active, `POST /messages` queues a new
   run with `mode: message`, `resume_of` the latest run of the session and the message as the
   task. The runner executes the profile's `resume_command` with `$SANDBOX_SESSION` (the id the
   control plane captured from the harness output: Claude Code's `session_id`, Codex's
   `thread_id`) and the message in `$SANDBOX_RESUME_PROMPT`:

   ```yaml
   harness:
     resume_command: 'claude -p "$SANDBOX_RESUME_PROMPT" --resume "$SANDBOX_SESSION" --output-format stream-json --verbose'
   ```

   The delivery is reported as `resumed`. With no session to continue (a sandbox that never
   ran, or whose harness never reported a session) the message starts a fresh conversation
   (`new`). This path works with any harness, including plain `claude -p` and `codex exec`.

3. **An open conversation ends cleanly.** `POST /messages/close` (or `/runs/{run}/close`) sends a
   `run.close` control event; the runner closes the harness's stdin, the harness exits, the run
   finishes with its exit code and usage. In `stream-json` mode the runner also closes the
   conversation by itself after `chat_idle` seconds without a message following a completed turn
   (default 10 minutes), so an idle chat does not hold a pod and a run open forever. The next
   message resumes the session (point 2). Cancelling a run (`/cancel`) still kills the harness.

Forced rollouts keep working on the same mechanism: the interrupted run is re-queued with
`mode: resume` and the harness is told to continue where it left off.

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

Paths are relative to `/workspace` (a leading `/workspace/` is accepted). The runner refuses
anything that resolves outside the workspace, through `..` or through a symlink. Transfer blob
names are confined to the sandbox that owns them (`fs/<sandbox>/…`): a pod can neither read
another sandbox's upload nor answer another sandbox's request, and uncollected blobs are purged
after an hour.

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
