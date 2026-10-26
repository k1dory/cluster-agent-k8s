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
    expires_at      timestamptz,
    preview_port    integer,
    preview_access  text,
    preview_host    text,
    error           text NOT NULL DEFAULT ''
);
ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS expires_at timestamptz;
CREATE INDEX IF NOT EXISTS sandboxes_tenant ON sandboxes (tenant, created_at, id);
CREATE UNIQUE INDEX IF NOT EXISTS sandboxes_preview_host ON sandboxes (preview_host) WHERE preview_host IS NOT NULL;

-- Runs and events are the accounting record: no foreign key to sandboxes, so deleting a
-- sandbox does not erase what it cost. tenant/slug are copied in for that reason.
CREATE TABLE IF NOT EXISTS runs (
    id                 text PRIMARY KEY,
    sandbox_id         text NOT NULL,
    tenant             text NOT NULL DEFAULT '',
    slug               text NOT NULL DEFAULT '',
    task               text NOT NULL,
    status             text NOT NULL,
    exit_code          integer NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL,
    started_at         timestamptz,
    finished_at        timestamptz,
    model              text NOT NULL DEFAULT '',
    input_tokens       bigint NOT NULL DEFAULT 0,
    output_tokens      bigint NOT NULL DEFAULT 0,
    cache_read_tokens  bigint NOT NULL DEFAULT 0,
    cache_write_tokens bigint NOT NULL DEFAULT 0,
    cost_usd           double precision NOT NULL DEFAULT 0,
    turns              integer NOT NULL DEFAULT 0
);
ALTER TABLE runs DROP CONSTRAINT IF EXISTS runs_sandbox_id_fkey;
ALTER TABLE runs
    ADD COLUMN IF NOT EXISTS tenant text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS slug text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS model text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS input_tokens bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS output_tokens bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cache_read_tokens bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cache_write_tokens bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS cost_usd double precision NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS turns integer NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS runs_sandbox ON runs (sandbox_id, created_at);
CREATE INDEX IF NOT EXISTS runs_tenant ON runs (tenant, created_at);
CREATE INDEX IF NOT EXISTS runs_slug ON runs (slug, created_at);

CREATE TABLE IF NOT EXISTS events (
    id          bigserial PRIMARY KEY,
    sandbox_id  text NOT NULL,
    tenant      text NOT NULL DEFAULT '',
    slug        text NOT NULL DEFAULT '',
    run_id      text NOT NULL DEFAULT '',
    type        text NOT NULL,
    data        text NOT NULL DEFAULT '',
    at          timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE events
    ADD COLUMN IF NOT EXISTS tenant text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS slug text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS events_sandbox ON events (sandbox_id, id);
CREATE INDEX IF NOT EXISTS events_sandbox_type ON events (sandbox_id, type, id);
CREATE INDEX IF NOT EXISTS events_tenant ON events (tenant, id);
CREATE INDEX IF NOT EXISTS events_type_at ON events (type, at);

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

-- Idempotency-Key reservations and stored responses (24h). status 0 = request in progress.
CREATE TABLE IF NOT EXISTS idempotency (
    key        text PRIMARY KEY,
    body_hash  text NOT NULL DEFAULT '',
    status     integer NOT NULL,
    body       bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE idempotency ADD COLUMN IF NOT EXISTS body_hash text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idempotency_created ON idempotency (created_at);

-- Agent versioning and optimistic locking (see model.Sandbox).
ALTER TABLE sandboxes
    ADD COLUMN IF NOT EXISTS agent_version text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS desired_version text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS env_version text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS revision bigint NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS sandboxes_instance ON sandboxes (instance);
ALTER TABLE runs
    ADD COLUMN IF NOT EXISTS agent_version text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS resume_of text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS session text NOT NULL DEFAULT '';
-- Conversation continuity: how a run relates to the one it continues (resume | message).
ALTER TABLE runs ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT '';

-- Shared blobs: the agent CA (certificate + key) when replicas must sign with one key.
CREATE TABLE IF NOT EXISTS blobs (
    name       text PRIMARY KEY,
    data       bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE sandboxes ADD COLUMN IF NOT EXISTS admin_grant boolean NOT NULL DEFAULT false;

-- Catalogue: AgentDefinition / EnvironmentProfile revisions (append-only, latest = current).
CREATE TABLE IF NOT EXISTS catalog_items (
    kind        text NOT NULL,
    tenant      text NOT NULL DEFAULT '',
    name        text NOT NULL,
    revision    integer NOT NULL,
    description text NOT NULL DEFAULT '',
    spec        jsonb NOT NULL,
    created_by  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, tenant, name, revision)
);
-- Deletion keeps history: revisions are marked, never removed, and numbers are never reused.
ALTER TABLE catalog_items ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
-- Provenance of a revision: the apply that wrote it and the Git commit its bundle came from
-- (model.Source as JSON); NULL for a revision written directly through the resource API.
ALTER TABLE catalog_items ADD COLUMN IF NOT EXISTS source jsonb;
ALTER TABLE sandboxes
    ADD COLUMN IF NOT EXISTS agent_ref text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS agent_revision integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS environment_ref text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS environment_revision integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS launch jsonb,
    ADD COLUMN IF NOT EXISTS connections jsonb;
ALTER TABLE runs
    ADD COLUMN IF NOT EXISTS agent_ref text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS agent_revision integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS environment_ref text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS environment_revision integer NOT NULL DEFAULT 0;

-- Applies: one application of a bundle, continued by key, a step written with its item in
-- one transaction (see store.Applies).
CREATE TABLE IF NOT EXISTS applies (
    id         text PRIMARY KEY,
    key        text NOT NULL,
    tenant     text NOT NULL DEFAULT '',
    status     text NOT NULL,
    doc        jsonb NOT NULL,
    version    bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant, key)
);

-- Tenant API keys: created, rotated and revoked through the API; only the secret's hash is kept.
CREATE TABLE IF NOT EXISTS api_keys (
    id           text PRIMARY KEY,
    tenant       text NOT NULL,
    name         text NOT NULL DEFAULT '',
    hash         text NOT NULL,
    created_by   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    revoked_at   timestamptz,
    rotated_to   text NOT NULL DEFAULT '',
    last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS api_keys_tenant ON api_keys (tenant, created_at DESC);
-- trust names the CITrust that issued a key to a CI job (short-lived; pruned once long expired).
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS trust text NOT NULL DEFAULT '';
-- Tokens used once (a CI provider's ID token exchanged for a key), until they expire anyway.
CREATE TABLE IF NOT EXISTS token_uses (
    id         text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
-- key_id: the key the token was exchanged for, written in the same transaction as the key.
ALTER TABLE token_uses ADD COLUMN IF NOT EXISTS key_id text NOT NULL DEFAULT '';

-- Tenant-brought credentials (BYOK): ciphertext only; the server key never touches the database.
CREATE TABLE IF NOT EXISTS credentials (
    tenant      text NOT NULL DEFAULT '',
    name        text NOT NULL,
    version     integer NOT NULL DEFAULT 1,
    fingerprint text NOT NULL DEFAULT '',
    ciphertext  bytea NOT NULL,
    created_by  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, name)
);

-- Git repositories: the last check and the last sync of each GitRepository (model.GitSync);
-- the applies and the revisions carry the history.
CREATE TABLE IF NOT EXISTS git_syncs (
    tenant     text NOT NULL DEFAULT '',
    name       text NOT NULL,
    doc        jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, name)
);

-- Records written before the record had two halves kept check and sync fields at the root.
-- Each half missing in the new form is built from those fields (a half already written in the
-- new form wins), then the root fields go. Idempotent: a converted record has no root field.
UPDATE git_syncs SET doc =
    (doc - 'tenant' - 'name' - 'head' - 'checked_at' - 'check_error' - 'commit' - 'bundles' - 'status' - 'error' - 'synced_at' - 'updated_at')
    || CASE WHEN doc ? 'check' OR NOT (doc ? 'checked_at') THEN '{}'::jsonb
            ELSE jsonb_build_object('check', jsonb_strip_nulls(jsonb_build_object('head', doc->'head', 'at', doc->'checked_at', 'error', doc->'check_error'))) END
    || CASE WHEN doc ? 'sync' OR NOT (doc ? 'synced_at') THEN '{}'::jsonb
            ELSE jsonb_build_object('sync', jsonb_strip_nulls(jsonb_build_object('commit', doc->'commit', 'bundles', doc->'bundles', 'status', doc->'status', 'error', doc->'error', 'at', doc->'synced_at'))) END
WHERE doc ?| array['checked_at', 'synced_at', 'head', 'commit', 'status', 'bundles', 'check_error', 'tenant', 'name', 'updated_at'];

-- Webhook jobs (model.GitJob): an accepted delivery survives the replica that accepted it; one
-- job per delivery; claimed under a lease by one replica at a time (store.GitJobs).
CREATE TABLE IF NOT EXISTS git_jobs (
    id          text PRIMARY KEY,
    tenant      text NOT NULL DEFAULT '',
    name        text NOT NULL,
    action      text NOT NULL,
    delivery    text NOT NULL,
    payload     bytea NOT NULL,
    status      text NOT NULL,
    attempts    integer NOT NULL DEFAULT 0,
    owner       text NOT NULL DEFAULT '',
    lease_until timestamptz,
    outcome     text NOT NULL DEFAULT '',
    error       text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant, name, delivery)
);
CREATE INDEX IF NOT EXISTS git_jobs_waiting ON git_jobs (status, lease_until, created_at);
-- run counts a job's executions for good (attempts starts over when a redelivery requeues
-- the job): the identity an execution's writes are fenced by. Rows from before carry their
-- attempts as the executions so far.
ALTER TABLE git_jobs ADD COLUMN IF NOT EXISTS run integer NOT NULL DEFAULT 0;
UPDATE git_jobs SET run = attempts WHERE run = 0 AND attempts > 0;
