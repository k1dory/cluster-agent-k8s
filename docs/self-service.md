# Self-service: keys, MCP servers and agents without touching the cluster

Everything a team needs to put an agent to work lives behind the one API: its credentials, the
services the agent may reach, the agent itself. The platform operator deploys the cluster once
(the chart, the policy repository, the secrets provider); onboarding a tenant, connecting an MCP
server or launching an agent never means editing a manifest, a ConfigMap or a Helm value. This
document walks the whole path and says where the admin still decides.

## 1. A tenant gets its key

```sh
sandboxctl keys create -tenant acme -name bootstrap        # admin; prints sbk_… once
```

From here on the tenant works with its own key. It issues one per pipeline or person, rotates
them, revokes a leaked one, and the admin is not in the loop:

```sh
export SANDBOXD_TOKEN=sbk_…                                 # sandboxctl reads SANDBOXD_URL and SANDBOXD_TOKEN
sandboxctl keys create -name ci -ttl 720h
sandboxctl keys rotate key_3f2a9c1e7b04 -grace 1h           # both secrets work for an hour
sandboxctl keys revoke key_3f2a9c1e7b04                     # refused on the very next request
```

The store keeps a key's id and the SHA-256 of its secret; every request looks the key up, so a
revocation holds on every replica at once and never waits for a cache. `api_keys.max_ttl` in the
server configuration caps how long a key may live. See the README, "Authentication".

## 1b. The tenant brings its own keys

An LLM key, an MCP token or a Git credential used to be something the operator placed in the
secrets provider for the tenant. Now the tenant puts it in itself, through the same API, and
replaces or revokes it without asking:

```sh
printf '%s' "$ANTHROPIC_API_KEY" | sandboxctl credentials set anthropic   # the value: stdin or -file, never argv
sandboxctl credentials list                                               # name, version, fingerprint, who, when
sandboxctl credentials set anthropic -file ./new-key.txt                 # replace: version 2 on the next request
sandboxctl credentials remove anthropic                                   # revoke: gone on the next request (see below)
```

`PUT /v1/credentials/{name}` with `{"value": …}`, `GET` (metadata only, a `fingerprint` of the
value to tell which one is loaded), `DELETE`. The value is encrypted at rest under the server's
`credentials.key` and exists in clear only inside the gateway's decision for that tenant.
`secret:NAME` references in connections and policies resolve in this order: the tenant's own
credential, a shared one of the same name (the admin's), the operator's provider. So a tenant
may override what the operator configured under the same name, and the operator's provider
keeps serving everything the tenant did not bring. Removing a credential takes the tenant's
value out of that chain on the next request: if nothing else carries the name, the request that
needs it fails at the gateway (502, nothing partial is sent); if a shared or operator credential
of the same name exists, that one is used again. A key the tenant wants gone everywhere is
removed where it lives.

## 1c. Subscriptions instead of API keys

A harness can run on its vendor's subscription rather than on an API key, with the same rule as
every other credential: the secret stays with the gateway, the pod holds a placeholder.

**Claude Code on a Claude subscription.** `claude setup-token` (on the tenant's own machine)
prints a long-lived OAuth token, `sk-ant-oat01-…`. The tenant stores it like any credential:

```sh
claude setup-token                                    # sign in in the browser, copy the token
sandboxctl credentials set claude-oauth               # paste it on stdin (Ctrl-D)
```

The policy injects it as the bearer, and nothing else
([examples/policies/llm-subscriptions.yaml](../examples/policies/llm-subscriptions.yaml)):

```yaml
- host: api.anthropic.com
  paths: ["/v1/**"]
  inject:
    Authorization: "Bearer secret:claude-oauth"
```

The environment profile gives Claude Code a placeholder token and no API key
([examples/catalog/environment-claude-subscription.yaml](../examples/catalog/environment-claude-subscription.yaml)):

```yaml
env:
  CLAUDE_CODE_OAUTH_TOKEN: sk-ant-oat01-placeholder-the-gateway-injects-the-real-token
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1"
```

What happens on the wire (checked against Claude Code 2.1.308, the version the agent image
pins): with `CLAUDE_CODE_OAUTH_TOKEN` set, Claude Code calls `POST /v1/messages?beta=true` with
`Authorization: Bearer <placeholder>` and `anthropic-beta: claude-code-20250219,
oauth-2025-04-20,…`, and no `x-api-key`. The gateway strips every header a policy injects for the
host before it asks sandboxd, then copies sandboxd's verdict: the placeholder is gone, the
tenant's token is in its place. `anthropic-beta` is not injected, so the agent's own list,
including the `oauth-2025-04-20` beta the API requires for OAuth tokens, passes untouched;
injecting it would replace the list. Two things break the swap: an `ANTHROPIC_API_KEY` in the
profile (Claude Code prefers it and sends `x-api-key`, which the API then prefers over the
bearer), and a rule for the same host that injects `x-api-key` for this slug.
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` keeps Claude Code to the Messages API, so nothing
else needs a rule. The token is the tenant's; rotating it is `credentials set` again, `credentials
remove` stops its use here at once, and the grant itself is revoked on the Anthropic account.

**Codex on a ChatGPT subscription.** A ChatGPT login is not a token one can paste: its access
token lives about an hour and its refresh token rotates on every use. So sandboxd signs in
itself, with the device flow Codex CLI uses (`codex login --device-auth`), and keeps the tokens:

```sh
sandboxctl oauth login chatgpt -provider chatgpt
# Open https://auth.openai.com/codex/device and enter the code ABCD-EFGH before 14:05.
# oauth chatgpt: active (provider chatgpt, account …); secret:chatgpt is its access token, …
sandboxctl oauth list                     # status, account, when the access token expires, last error
sandboxctl oauth remove chatgpt           # forget it (revoke the grant itself at OpenAI)
```

`POST /v1/oauth-credentials/{name}/login` with `{"provider": "chatgpt"}` asks the provider for a
user code and returns the pending sign-in (`verification_url`, `user_code`,
`login_expires_at`); the person opens the URL, signs in and types the code. Every replica polls
the pending sign-ins at the provider's interval and refreshes the active ones five minutes before
their access token expires; a lease on the row lets one replica at a time talk to the provider
for a sign-in, because a refresh token spent twice is a revoked grant. Then `secret:chatgpt`
resolves to the current access token and `secret:chatgpt.account_id` to the ChatGPT account id
from the ID token, so the policy injects both
([examples/policies/llm-subscriptions.yaml](../examples/policies/llm-subscriptions.yaml)):

```yaml
- host: chatgpt.com
  paths: ["/backend-api/codex/**"]
  inject:
    Authorization: "Bearer secret:chatgpt"
    ChatGPT-Account-ID: "secret:chatgpt.account_id"
```

Codex in the pod uses a provider pointed at the ChatGPT backend whose key is a placeholder
([examples/catalog/environment-codex-chatgpt.yaml](../examples/catalog/environment-codex-chatgpt.yaml),
which writes `~/.codex/config.toml` through the harness files below), so neither the refresh
token nor the access token is ever in the pod. A sign-in nobody approves within fifteen minutes,
a denied one, and a refresh token the provider revokes, expires or finds reused end as `failed`
with the reason: the gateway then answers 502 with it, and `oauth login` again is the fix. A
provider outage keeps the sign-in and retries. The tokens are encrypted under
`credentials.key` like every credential; the API returns only state, never a token or the
device code. A name is a sign-in or a plain credential in a scope, never both.

The providers are server configuration (`credentials.oauth.providers` in sandboxd.yaml,
`sandboxd.credentialsOAuth` in the chart). `chatgpt` is built in with the endpoints and the
public client id of Codex CLI (openai/codex, `codex-rs/login`); an entry overrides any of its
fields, and another provider speaking RFC 8628 (`device_style: rfc8628`) can be added the same
way.

**Harness configuration files.** A harness that reads its settings from a file (Codex's
`~/.codex/config.toml`, Claude Code's `~/.claude/settings.json`) gets them from the profile:

```yaml
spec:
  harness:
    files:                            # path inside the agent's home → content
      .codex/config.toml: |
        model_provider = "gateway"
```

The runner writes them before every run (mode 0600), replacing what the harness changed in
between, so the profile stays the truth. Paths are clean relative paths inside the home
directory; at most 16 files and 32 KiB together, since they travel in the pod's environment
(`SANDBOX_HARNESS_FILES`). They are configuration, stored in the clear with the profile and
visible in the pod spec: a secret in them is a mistake, a `secret:NAME` the gateway injects is
the way. A deployment keeps its real profiles (provider endpoints, model names) in its own
configuration repository and applies them with `sandboxctl apply`; the repository's examples
stay generic.

## 2. The admin decides what the tenant may reach

Two admin-written resources, both through the API (`sandboxctl apply`, a PUT, or a bundle from
Git), replace what used to be a policy file edit:

- a **PolicyBinding** grants the tenant a policy slug from the repository (the network rules
  the operator reviewed), with an expiry and per-slug limits;
- **TenantSettings** `hosts` lists the hosts the tenant may reach through connections of its
  own, beyond what the repository serves: exact names or `*.suffix`.

```yaml
kind: TenantSettings
spec:
  hosts: ["mcp.tools.example.com", "*.internal.example.com"]
```

A host the policy repository already serves needs no entry: a connection for it only adds
headers, and the repository's rule (paths, methods, injections, MCP restrictions) stays in
force. The repository remains the place for anything reviewed as code; `hosts` is the admin
delegating a bounded part of egress to the tenant, revocable with one apply.

## 3. The tenant connects an MCP server

```yaml
kind: Connection
name: tools
spec:
  type: mcp
  host: mcp.tools.example.com
  upstream: https://10.0.0.5:8443            # optional: where the gateway sends it (default https://host)
  paths: ["/mcp", "/mcp/**"]                 # optional: what the agent may call (default /**)
  mcp: { read_only: true, tools: ["get_*", "list_*"] }   # optional: what the proxy lets through
  headers:
    Authorization: Bearer secret:tools-token # a credential is always a reference
```

On the next gateway sync (seconds) the host is served: a site with the gateway's certificate
and strict SNI, DNS for the pods, `forward_auth` to sandboxd, and for `type: mcp` the MCP proxy
that inspects every JSON-RPC body. The connection is the rule for that host: only a sandbox that
carries the connection passes, only on its `paths`, with its `mcp` restriction, and with the
headers it names, resolved from the tenant's secrets at request time. A connection for a host
the tenant's settings do not list is refused (403) with the reason; two connections cannot send
one host to two upstreams or make it both HTTP and MCP; deleting the connection withdraws the
host and the rule immediately. The admin's shared connections (`-tenant ""`) may name any host.

An `upstream` behind a private CA is trusted once the operator names a ConfigMap of its PEM
roots in `gateway.upstreamCAConfigMap`: Caddy and the MCP proxy add them to the system roots.
The gateway sends the connection's host name as `Host` and, for an IP upstream, checks the
certificate against that name. A server that answers only to its own address (an IP site, a
certificate with the IP alone) takes `upstream_host: true`: the upstream's `host:port` is then
both the `Host` header and the name its certificate is checked against.

## 4. The agent, and the sandbox that runs it

```yaml
kind: EnvironmentProfile
name: py
spec: { image: stable }
---
kind: AgentDefinition
name: backend
spec:
  policy: backend-dev
  environment: py
  connections: [tools]
  instructions: Use the tools server for repository lookups.
```

```sh
sandboxctl apply -f agent.yaml
sandboxctl create -name shop -owner alice -agent backend
sandboxctl run sb_1234 "add integration tests for the checkout flow"
```

The sandbox records the agent's connections. Its pod gets `SANDBOX_MCP_SERVERS`, a JSON list of
the MCP endpoints those connections give it (`[{"name":"tools","url":"https://mcp.tools.example.com/mcp"}]`);
the runner writes them as a Claude Code MCP configuration (`$SANDBOX_MCP_CONFIG`) and the
default harness command loads it with `--mcp-config`. A custom `harness.command` names
`"$SANDBOX_MCP_CONFIG"` itself where it wants it. The gateway decides what each call may do; the
configuration only tells the harness where the servers are.

## What stays with the operator

- The policy repository: the slugs and the network rules reviewed as code, their `tenants:`
  lists, the hosts they serve. A connection never overrides a repository host.
- The secrets provider and `credentials.key`: a connection references `secret:NAME`; the value
  is what the tenant brought through the API (encrypted under the server key the operator holds)
  or, failing that, what the operator placed in the file directory, Vault/OpenBao or Infisical
  under the tenant's path.
- `TenantSettings.hosts` and `PolicyBinding`: what each tenant may reach and run. Both are API
  resources with history, so widening and revoking are one apply each, and the drift report shows
  when somebody changed them by hand.

## Where to read the state

```sh
sandboxctl keys list -tenant acme                 # API keys and when they were last used
sandboxctl credentials list                       # the tenant's own secrets: versions and fingerprints, never values
sandboxctl settings acme                          # hosts and environments the tenant may use
sandboxctl list connections                       # what the tenant declared
sandboxctl get sandbox sb_1234                    # connections and launch (mcp_servers) of a sandbox
sandboxctl trace -sandbox sb_1234                 # every allowed and denied request, host by host
```
