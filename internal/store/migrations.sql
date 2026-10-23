CREATE TABLE IF NOT EXISTS sandboxes (
    id              text PRIMARY KEY,
    name            text NOT NULL,
    slug            text NOT NULL,
    owner           text NOT NULL,
    tenant          text NOT NULL,
    repo            text NOT NULL DEFAULT '',
    idle_timeout    integer NOT NULL DEFAULT 3600,
    wake_on_preview boolean NOT NULL DEFAULT true,
    status          text NOT NULL,
    ip              text NOT NULL DEFAULT '',
    instance        integer NOT NULL DEFAULT 0,
    pod_name        text NOT NULL DEFAULT '',
    last_activity   timestamptz NOT NULL,
    created_at      timestamptz NOT NULL,
    preview_port    integer,
    preview_access  text,
    preview_host    text,
    error           text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS sandboxes_preview_host ON sandboxes (preview_host) WHERE preview_host IS NOT NULL;

CREATE TABLE IF NOT EXISTS runs (
    id          text PRIMARY KEY,
    sandbox_id  text NOT NULL REFERENCES sandboxes(id) ON DELETE CASCADE,
    task        text NOT NULL,
    status      text NOT NULL,
    exit_code   integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL,
    started_at  timestamptz,
    finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS runs_sandbox ON runs (sandbox_id, created_at);

CREATE TABLE IF NOT EXISTS events (
    id          bigserial PRIMARY KEY,
    sandbox_id  text NOT NULL,
    run_id      text NOT NULL DEFAULT '',
    type        text NOT NULL,
    data        text NOT NULL DEFAULT '',
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS events_sandbox ON events (sandbox_id, id);

-- Instance numbers come from a sequence: allocation is atomic and numbers are never reused.
CREATE SEQUENCE IF NOT EXISTS instance_seq;

CREATE TABLE IF NOT EXISTS instances (
    n           integer PRIMARY KEY,
    sandbox_id  text NOT NULL,
    slug        text NOT NULL,
    tenant      text NOT NULL,
    pod_name    text NOT NULL,
    serial      text NOT NULL UNIQUE,
    issued_at   timestamptz NOT NULL,
    not_after   timestamptz NOT NULL,
    retired_at  timestamptz
);
CREATE INDEX IF NOT EXISTS instances_sandbox ON instances (sandbox_id);
