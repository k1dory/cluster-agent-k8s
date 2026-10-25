// Package model holds the data types shared by the store, orchestrator and API.
package model

import (
	"encoding/json"
	"strings"
	"time"
)

// SandboxStatus is the lifecycle state of a sandbox.
type SandboxStatus string

const (
	StatusCreating SandboxStatus = "creating"
	StatusRunning  SandboxStatus = "running"
	StatusSleeping SandboxStatus = "sleeping"
	StatusWaking   SandboxStatus = "waking"
	StatusStopping SandboxStatus = "stopping"
	StatusDeleting SandboxStatus = "deleting" // delete requested; pod/volume removal pending or failed (see Error)
	StatusError    SandboxStatus = "error"
)

// Preview access levels, in increasing strictness.
const (
	AccessLink    = "link"
	AccessSSO     = "sso"
	AccessMembers = "members"
)

// Preview describes the application port exposed from the sandbox.
type Preview struct {
	Port   int    `json:"port"`
	Access string `json:"access"`
	Host   string `json:"host"`
}

// Launch is the resolved set of parameters a sandbox's pods start with: the environment
// profile's revision rendered at creation time and kept on the sandbox, so every wake and
// rollout of this sandbox uses the same configuration whatever the catalogue says later.
type Launch struct {
	Image                string `json:"image"`
	HarnessCommand       string `json:"harness_command,omitempty"`
	HarnessResumeCommand string `json:"harness_resume_command,omitempty"`
	ResumePrompt         string `json:"resume_prompt,omitempty"`
	// HarnessInput says how the runner hands messages to the harness: "text" (a line on stdin;
	// the default) or "stream-json" (Claude Code's streaming input: one JSON user message per
	// line, which keeps the conversation open for follow-ups). ChatIdle is how many seconds a
	// run in stream-json mode waits for the next message after a turn before the runner closes
	// the conversation (0 = the runtime default, 600).
	HarnessInput string `json:"harness_input,omitempty"`
	ChatIdle     int    `json:"chat_idle,omitempty"`
	Model        string `json:"model,omitempty"`        // exported as SANDBOX_MODEL and ANTHROPIC_MODEL
	Instructions string `json:"instructions,omitempty"` // exported as SANDBOX_INSTRUCTIONS
	// Env is the profile's own variables for the agent container. They never reach the init
	// containers and never shadow a platform variable (see PlatformEnv).
	Env map[string]string `json:"env,omitempty"`
	// MCPServers are the MCP endpoints the agent's connections give it, exported to the pod as
	// SANDBOX_MCP_SERVERS (JSON) so the harness can register them.
	MCPServers    []MCPServer `json:"mcp_servers,omitempty"`
	CPURequest    string      `json:"cpu_request,omitempty"`
	CPULimit      string      `json:"cpu_limit,omitempty"`
	MemoryRequest string      `json:"memory_request,omitempty"`
	MemoryLimit   string      `json:"memory_limit,omitempty"`
	VolumeSize    string      `json:"volume_size,omitempty"`
	RuntimeClass  string      `json:"runtime_class,omitempty"`
}

// MCPServer is one MCP endpoint of a launch: the connection's name and its URL.
type MCPServer struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// PlatformEnv reports whether an environment variable name belongs to the platform: the
// variables sandboxd sets on every pod to wire the agent to the gateway, the registrar and
// the API, and everything under SANDBOX_. A profile cannot set them; the runtime never lets a
// profile value replace one.
func PlatformEnv(name string) bool {
	if strings.HasPrefix(name, "SANDBOX_") {
		return true
	}
	switch name {
	case "GATEWAY_IP", "GATEWAY_CA_FILE", "REGISTRAR_URL", "API_URL", "CERT_DIR", "HOME",
		"HARNESS_CMD", "HARNESS_RESUME_CMD", "HARNESS_INPUT", "HARNESS_CHAT_IDLE":
		return true
	}
	return false
}

// CatalogItem is one revision of a catalogue resource: an AgentDefinition or an
// EnvironmentProfile. Revisions are append-only and their numbers are never reused: deleting
// an item marks its revisions deleted (DeletedAt) and keeps them as history; a later write
// under the same name continues the numbering. Tenant "" is a shared item the admin manages
// and every tenant may reference.
type CatalogItem struct {
	Kind        string          `json:"kind"`
	Tenant      string          `json:"tenant"`
	Name        string          `json:"name"`
	Revision    int             `json:"revision"`
	Description string          `json:"description,omitempty"`
	Spec        json.RawMessage `json:"spec"`
	CreatedBy   string          `json:"created_by,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	DeletedAt   *time.Time      `json:"deleted_at,omitempty"`
	// Source says where the revision came from: the apply that wrote it and, when the bundle was
	// taken from Git, the commit. Absent on a revision written directly through the resource API:
	// such a revision belongs to nobody, and on an item an apply wrote earlier it is drift.
	Source *Source `json:"source,omitempty"`
}

// Source is the provenance of a revision (or of an apply: what its documents came from).
type Source struct {
	Apply  string `json:"apply,omitempty"`  // the apply that wrote the revision
	Bundle string `json:"bundle,omitempty"` // fingerprint of the documents it applied
	Repo   string `json:"repo,omitempty"`   // Git remote the bundle was read from
	Ref    string `json:"ref,omitempty"`    // branch or tag
	Commit string `json:"commit,omitempty"` // the commit the bundle file matches (never a dirty tree)
	Path   string `json:"path,omitempty"`   // bundle file in the repository
	// Rollback names what the apply restored: another apply ("apply_…") or one revision
	// ("Kind tenant/name@N"). Set by the rollback controller, never by a plain apply.
	Rollback string `json:"rollback,omitempty"`
}

// Managed reports a revision an apply wrote.
func (it *CatalogItem) Managed() bool { return it.Source != nil && it.Source.Apply != "" }

// Versioned resource kinds (all stored as CatalogItems).
const (
	KindAgent          = "AgentDefinition"
	KindEnvironment    = "EnvironmentProfile"
	KindConnection     = "Connection"     // an external service an agent may use, credentials by reference
	KindBinding        = "PolicyBinding"  // the admin's grant of a policy slug to a tenant, with limits
	KindTenantSettings = "TenantSettings" // a tenant's quotas and allowed environments (name "settings")
	KindGitRepository  = "GitRepository"  // a Git repository of bundles the platform reads itself
	KindCITrust        = "CITrust"        // what a CI provider asserts about a job, trusted to act as the tenant for minutes
)

// GitSync is the state of a GitRepository as the platform last saw it: the last check (the
// ref's head) and the last sync (what was applied). The two halves are written independently
// and atomically: a check never touches the sync half and a sync never touches the check half,
// so a check racing a sync cannot erase the sync's commit and apply ids. One record per
// repository; the history of what was written is in the applies and the revisions.
type GitSync struct {
	Tenant    string         `json:"tenant"`
	Name      string         `json:"name"`
	Check     *GitCheck      `json:"check,omitempty"`
	Sync      *GitSyncResult `json:"sync,omitempty"`
	Hook      *GitHook       `json:"hook,omitempty"` // the last webhook delivery handled
	UpdatedAt time.Time      `json:"updated_at"`
}

// GitHook is the last webhook delivery the platform handled for the repository: what the
// provider sent, what the platform did with it and how it went. The third half of the record,
// written on its own like the other two.
type GitHook struct {
	Provider string    `json:"provider"`           // github | gitlab
	Event    string    `json:"event"`              // push | pull_request | merge_request | <other, ignored>
	Action   string    `json:"action,omitempty"`   // what the platform did: sync | plan | ignored
	Reason   string    `json:"reason,omitempty"`   // why it was ignored, or how the action went
	Ref      string    `json:"ref,omitempty"`      // the ref the delivery named
	Commit   string    `json:"commit,omitempty"`   // the commit it named (head of the push or of the pull request)
	Number   int       `json:"number,omitempty"`   // the pull/merge request number
	Delivery string    `json:"delivery,omitempty"` // the provider's delivery id
	Job      string    `json:"job,omitempty"`      // the persisted job that carries the action out
	Run      int       `json:"run,omitempty"`      // the job's execution this outcome is from (GitJob.Run; 0: the acceptance)
	Attempt  int       `json:"attempt,omitempty"`  // that execution's number within the job's current budget of MaxAttempts
	Outcome  string    `json:"outcome,omitempty"`  // done | invalid | stopped | error | ignored | superseded
	Error    string    `json:"error,omitempty"`
	At       time.Time `json:"at"`
}

// Webhook actions and outcomes (GitHook.Action / Outcome).
const (
	HookActionSync    = "sync"
	HookActionPlan    = "plan"
	HookActionIgnored = "ignored"
	HookIgnored       = "ignored"
	HookSuperseded    = "superseded" // a delivery whose commit the ref (or the pull request) had already moved past
)

// GitJob is a webhook action waiting to run or running: persisted when the delivery is
// accepted, claimed by one replica at a time under a lease, finished with an outcome. A replica
// that dies mid-way leaves a job whose lease lapses, and another replica picks it up; the work
// itself (a sync, a plan comment) is idempotent, so a repeat is harmless.
type GitJob struct {
	ID         string     `json:"id"`
	Tenant     string     `json:"tenant"`
	Name       string     `json:"name"`            // the repository
	Action     string     `json:"action"`          // sync | plan
	Delivery   string     `json:"delivery"`        // provider + delivery id: the same delivery is never two jobs
	Payload    []byte     `json:"payload"`         // the delivery, reduced (gitsync.Delivery)
	Status     string     `json:"status"`          // pending | running | done | failed
	Attempts   int        `json:"attempts"`        // executions within the current budget; reset when a redelivery requeues the job
	Run        int        `json:"run"`             // executions ever: one more per claim, never reset; the identity of an execution's writes
	Owner      string     `json:"owner,omitempty"` // the replica running it
	LeaseUntil *time.Time `json:"lease_until,omitempty"`
	Outcome    string     `json:"outcome,omitempty"`
	Error      string     `json:"error,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// GitJob statuses.
const (
	GitJobPending = "pending"
	GitJobRunning = "running"
	GitJobDone    = "done"
	GitJobFailed  = "failed"
)

// GitCheck is the last check: the ref's head, or why it could not be read.
type GitCheck struct {
	Head  string    `json:"head,omitempty"`
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`
}

// GitSyncResult is the last sync attempt: the commit, one entry per bundle in apply order,
// and the outcome. Generation counts the transitions of the desired state: it moves on when
// a sync names another commit than the last one did, so going back to a commit synced before
// (a force push A → B → A) is a new transition with applies of its own, while a repeat of the
// same commit (a retry, a continued stopped apply, a redelivery) finds the applies it had.
type GitSyncResult struct {
	Commit     string          `json:"commit,omitempty"`
	Generation int             `json:"generation,omitempty"`
	Bundles    []GitSyncBundle `json:"bundles,omitempty"`
	Status     string          `json:"status"` // done | invalid | stopped | error
	Error      string          `json:"error,omitempty"`
	At         time.Time       `json:"at"`
}

// GitSync statuses.
const (
	GitSyncRunning = "running" // the transition is fixed (commit and generation) and the bundles are being applied
	GitSyncDone    = "done"    // every bundle applied
	GitSyncInvalid = "invalid" // a bundle's plan was refused; nothing of it was written
	GitSyncStopped = "stopped" // an apply did not finish (failed or conflict): continue by syncing the same commit again
	GitSyncError   = "error"   // the repository could not be read (unreachable, refused, the commit not on the ref)
)

// GitSyncBundle is one bundle file of a sync.
type GitSyncBundle struct {
	Path    string   `json:"path"`
	Apply   string   `json:"apply,omitempty"`   // the apply that wrote (or is writing) it
	Status  string   `json:"status"`            // the apply's status, or "invalid"
	Changes int      `json:"changes,omitempty"` // creates + updates of its plan
	Errors  []string `json:"errors,omitempty"`
}

// Sandbox is one agent workspace: a persistent volume plus, while awake, one pod.
//
// Versions: AgentVersion is the agent image the current (or last) pod runs; DesiredVersion is
// a rollout target not yet applied (empty when none); EnvVersion identifies the environment the
// pod was started under (policy content, harness command, image, pod env). Revision is the
// optimistic-locking counter every update must match.
type Sandbox struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Slug          string        `json:"slug"`
	Owner         string        `json:"owner"`
	Tenant        string        `json:"tenant"`
	Repo          string        `json:"repo"`
	IdleTimeout   int           `json:"idle_timeout"` // seconds; 0 = never sleep
	WakeOnPreview bool          `json:"wake_on_preview"`
	Status        SandboxStatus `json:"status"`
	IP            string        `json:"ip,omitempty"`
	Instance      int           `json:"instance"`
	PodName       string        `json:"pod_name,omitempty"`
	// AdminGrant: the admin created this sandbox for a slug its tenant does not own. The grant
	// lives in the agent certificate and in policy.Set.Revoked; see there for what ends it.
	AdminGrant bool `json:"admin_grant,omitempty"`
	// Catalogue references resolved at creation: which AgentDefinition and EnvironmentProfile
	// revisions this sandbox was built from ("name", or "shared/name" for a shared item, so
	// the scope is part of the record), and the Launch rendered from them. Empty for
	// sandboxes created with a bare slug.
	AgentRef            string  `json:"agent_ref,omitempty"`
	AgentRevision       int     `json:"agent_revision,omitempty"`
	EnvironmentRef      string  `json:"environment_ref,omitempty"`
	EnvironmentRevision int     `json:"environment_revision,omitempty"`
	Launch              *Launch `json:"launch,omitempty"`
	// Connections the agent uses (references as seen from this tenant: "name" or
	// "shared/name"), fixed at creation; the gateway adds their headers to matching hosts.
	Connections    []string   `json:"connections,omitempty"`
	AgentVersion   string     `json:"agent_version"`
	DesiredVersion string     `json:"desired_version,omitempty"`
	EnvVersion     string     `json:"env_version,omitempty"`
	Revision       int64      `json:"revision"`
	LastActivity   time.Time  `json:"last_activity"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"` // when set, the sandbox is deleted after this time
	Preview        *Preview   `json:"preview,omitempty"`
	Error          string     `json:"error,omitempty"`
}

// IdleDuration returns the idle timeout as a duration.
func (s *Sandbox) IdleDuration() time.Duration { return time.Duration(s.IdleTimeout) * time.Second }

// RunStatus is the lifecycle state of one agent run (one task).
type RunStatus string

const (
	RunQueued    RunStatus = "queued"
	RunRunning   RunStatus = "running"
	RunDone      RunStatus = "done"
	RunFailed    RunStatus = "failed"
	RunCancelled RunStatus = "cancelled"
)

// Usage is what one run consumed on the model side. It is reported by the harness
// (Claude Code's stream-json `result` line is understood natively; any harness can emit
// a `{"type":"usage",...}` line or send it with /finish) and is the basis of cost accounting.
type Usage struct {
	Model        string  `json:"model,omitempty"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CacheRead    int64   `json:"cache_read_tokens"`
	CacheWrite   int64   `json:"cache_write_tokens"`
	CostUSD      float64 `json:"cost_usd"`
	Turns        int     `json:"turns"`
}

// Add accumulates another usage record into u.
func (u *Usage) Add(o Usage) {
	if o.Model != "" {
		u.Model = o.Model
	}
	u.InputTokens += o.InputTokens
	u.OutputTokens += o.OutputTokens
	u.CacheRead += o.CacheRead
	u.CacheWrite += o.CacheWrite
	u.CostUSD += o.CostUSD
	u.Turns += o.Turns
}

// IsZero reports whether nothing was recorded.
func (u Usage) IsZero() bool {
	return u.InputTokens == 0 && u.OutputTokens == 0 && u.CacheRead == 0 && u.CacheWrite == 0 && u.CostUSD == 0 && u.Turns == 0
}

// Run is one task handed to the agent inside a sandbox. Tenant and slug are copied from the
// sandbox so accounting survives the sandbox being deleted.
type Run struct {
	ID        string    `json:"id"`
	SandboxID string    `json:"sandbox_id"`
	Tenant    string    `json:"tenant,omitempty"`
	Slug      string    `json:"slug,omitempty"`
	Task      string    `json:"task"`
	Status    RunStatus `json:"status"`
	ExitCode  int       `json:"exit_code"`
	Usage     Usage     `json:"usage"`
	// AgentVersion is the agent image that executed the run (set when the run is claimed), and
	// the catalogue revisions the sandbox was running under at that moment. They never change
	// afterwards: a definition updated mid-run does not touch the run.
	AgentVersion        string `json:"agent_version,omitempty"`
	AgentRef            string `json:"agent_ref,omitempty"`
	AgentRevision       int    `json:"agent_revision,omitempty"`
	EnvironmentRef      string `json:"environment_ref,omitempty"`
	EnvironmentRevision int    `json:"environment_revision,omitempty"`
	// ResumeOf names the run this one continues: after a forced rollout interrupted it (Mode
	// RunResume: the task is the original one, the harness is told to carry on), or as the next
	// message of the same conversation (Mode RunMessage: the task is the message).
	ResumeOf string `json:"resume_of,omitempty"`
	Mode     string `json:"mode,omitempty"`
	// Session is the harness's own conversation id (Claude Code `session_id`, Codex thread id),
	// captured from the output stream so a resume run can continue where the agent stopped.
	Session    string     `json:"session,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// Run modes (Mode): how the run relates to the conversation.
const (
	RunTask    = ""        // a fresh task: a new conversation
	RunResume  = "resume"  // continues ResumeOf after a rollout interrupted it
	RunMessage = "message" // the next message of the conversation ResumeOf belongs to
)

// Message is one turn of a sandbox's conversation, derived from the event stream: what the
// user sent (run tasks and inputs) and what the agent answered (assistant text pulled out of
// the harness output), with run boundaries as system notes. ID is the event it came from, so
// a client resumes with ?after=.
type Message struct {
	ID    int64     `json:"id"`
	RunID string    `json:"run_id,omitempty"`
	Role  string    `json:"role"` // user | assistant | tool | system | log
	Text  string    `json:"text"`
	At    time.Time `json:"at"`
}

// Message roles.
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool"   // a tool call the agent made (name only)
	RoleSystem    = "system" // run boundaries: queued, resumed, finished
	RoleLog       = "log"    // raw harness output that is not a message (only with raw=true)
)

// FSRequest is the payload of an fs.request event: one file operation the control plane
// asks the running pod to perform in its workspace. Paths are relative to /workspace.
type FSRequest struct {
	ID    string `json:"id"`
	Op    string `json:"op"` // list | read | write
	Path  string `json:"path"`
	Depth int    `json:"depth,omitempty"` // list: levels below Path to include (1 = Path's entries)
	Blob  string `json:"blob,omitempty"`  // write: the blob holding the content to write
}

// FSEntry is one entry of a listing.
type FSEntry struct {
	Path    string    `json:"path"`
	Type    string    `json:"type"` // file | dir | symlink | other
	Size    int64     `json:"size,omitempty"`
	ModTime time.Time `json:"mod_time"`
}

// FSResult is the payload of an fs.result event: the pod's answer to one FSRequest.
type FSResult struct {
	Request     string    `json:"request"`
	OK          bool      `json:"ok"`
	Error       string    `json:"error,omitempty"`
	Entries     []FSEntry `json:"entries,omitempty"`      // list
	Truncated   bool      `json:"truncated,omitempty"`    // list: more entries than the limit
	Blob        string    `json:"blob,omitempty"`         // read: the blob holding the content
	Size        int64     `json:"size,omitempty"`         // read / write
	ContentType string    `json:"content_type,omitempty"` // read
}

// File operations.
const (
	FSList  = "list"
	FSRead  = "read"
	FSWrite = "write"
)

// Apply is one application of a bundle of configuration documents: the plan it was made
// from, frozen with the revisions it expects and will produce, and the progress of each step.
// It is created once per idempotency key and continued, never redone: a step is applied and
// marked done in one transaction, so a retry after any failure finds exactly what happened.
type Apply struct {
	ID        string          `json:"id"`
	Key       string          `json:"key"`    // idempotency key: the same key and bundle continue this apply
	Tenant    string          `json:"tenant"` // the scope it was submitted in ("" = shared / admin default)
	Admin     bool            `json:"admin"`
	Subject   string          `json:"subject,omitempty"`
	Bundle    string          `json:"bundle"` // fingerprint of the documents
	Plan      string          `json:"plan"`   // fingerprint of the plan (documents + scope + actions + revisions)
	Status    string          `json:"status"` // running | done | failed | conflict
	Error     string          `json:"error,omitempty"`
	Steps     []ApplyStep     `json:"steps"`
	Documents json.RawMessage `json:"documents"` // the bundle, as submitted (resume re-plans it)
	// Source is where the bundle came from (Git repo, ref, commit, path, or the rollback target);
	// every revision the apply writes carries it, plus the apply's own id and bundle.
	Source *Source `json:"source,omitempty"`
	// Lease: the replica executing the apply and until when; another replica waits for it to
	// lapse before continuing an unfinished apply.
	LeaseOwner string     `json:"lease_owner,omitempty"`
	LeaseUntil *time.Time `json:"lease_until,omitempty"`
	// Attempt counts lease takeovers: a worker writes only while the record still carries its
	// owner and attempt, so a replica that lost the lease cannot undo its successor's work.
	Attempt   int64     `json:"attempt"`
	Version   int64     `json:"version"` // optimistic-locking counter of the record
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ApplyStep is one document of the bundle in apply order.
type ApplyStep struct {
	Kind             string `json:"kind"`
	Tenant           string `json:"tenant"`
	Name             string `json:"name"`
	Action           string `json:"action"` // create | update | noop
	ExpectedRevision int    `json:"expected_revision"`
	NextRevision     int    `json:"next_revision"`
	Resolved         string `json:"resolved,omitempty"` // fingerprint of the item as planned (plan.Change.Resolved)
	Status           string `json:"status"`             // pending | done | skipped | failed
	Revision         int    `json:"revision,omitempty"` // the revision written (done) or confirmed (skipped)
	Error            string `json:"error,omitempty"`
}

// APIKey is a tenant-scoped credential for the platform API, created, rotated and revoked
// through the API itself (no configuration or manifest change). Only a hash of the secret is
// stored; the secret is shown once, at creation or rotation.
type APIKey struct {
	ID         string     `json:"id"`
	Tenant     string     `json:"tenant"`
	Name       string     `json:"name"`
	Hash       string     `json:"-"` // sha256 of the secret, hex
	CreatedBy  string     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RotatedTo  string     `json:"rotated_to,omitempty"` // the key that replaced this one
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// Trust names the CITrust that issued the key to a CI job (internal/ciauth): short-lived,
	// never rotated, pruned once long expired. Empty for a key a person or the admin created.
	Trust string `json:"trust,omitempty"`
}

// Credential is the metadata of a secret a tenant brought through the API (its own LLM key,
// MCP token or Git credential): what `secret:NAME` references resolve to first. The value is
// encrypted at rest and never leaves the gateway's decision; the API returns this record only.
type Credential struct {
	Tenant      string    `json:"tenant"` // "" = shared, written by the admin
	Name        string    `json:"name"`
	Version     int       `json:"version"`     // bumped by every replacement
	Fingerprint string    `json:"fingerprint"` // first 12 hex of sha256(value): tells which value is loaded, reveals nothing of it
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Active reports a key that authenticates at t: not revoked, not expired.
func (k *APIKey) Active(t time.Time) bool {
	if k.RevokedAt != nil && !k.RevokedAt.After(t) {
		return false
	}
	return k.ExpiresAt == nil || k.ExpiresAt.After(t)
}

// Apply and step statuses.
const (
	ApplyRunning  = "running"
	ApplyDone     = "done"
	ApplyFailed   = "failed"   // a step failed; the rest is pending, resume retries
	ApplyConflict = "conflict" // the state or the caller's rights moved; resume after a new plan

	StepPending = "pending"
	StepDone    = "done"
	StepSkipped = "skipped" // noop: the revision was confirmed unchanged
	StepFailed  = "failed"
)

// Seconds is the wall time the run has been executing (until now if still running).
func (r *Run) Seconds(now time.Time) float64 {
	if r.StartedAt == nil {
		return 0
	}
	end := now
	if r.FinishedAt != nil {
		end = *r.FinishedAt
	}
	if end.Before(*r.StartedAt) {
		return 0
	}
	return end.Sub(*r.StartedAt).Seconds()
}

// Event is one line of the sandbox event stream (agent output, status changes, egress).
// Tenant and slug are denormalised so a tenant-wide trace is one indexed query.
type Event struct {
	ID        int64     `json:"id"`
	SandboxID string    `json:"sandbox_id"`
	Tenant    string    `json:"tenant,omitempty"`
	Slug      string    `json:"slug,omitempty"`
	RunID     string    `json:"run_id,omitempty"`
	Type      string    `json:"type"`
	Data      string    `json:"data,omitempty"`
	At        time.Time `json:"at"`
}

// Egress is the payload of an egress.* event: one request the agent made through the gateway.
type Egress struct {
	Host   string `json:"host"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Code   int    `json:"code,omitempty"`   // on deny: the status the gateway answered
	Reason string `json:"reason,omitempty"` // on deny: why
}

// Rollout is the payload of a rollout event: one sandbox moving to another agent version.
type Rollout struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Mode: now (pod restarted at once), forced (run interrupted and re-queued as a resume),
	// deferred (applied when the current run finishes), wake (applied on the next wake).
	Mode     string `json:"mode"`
	RunID    string `json:"run_id,omitempty"`    // forced: the interrupted run
	ResumeID string `json:"resume_id,omitempty"` // forced: the run that continues it
}

// Rollout modes.
const (
	RolloutNow      = "now"
	RolloutForced   = "forced"
	RolloutDeferred = "deferred"
	RolloutWake     = "wake"
)

// Event types.
const (
	EventStatus    = "status"
	EventRunQueued = "run.queued"
	EventRunStart  = "run.started"
	EventRunOutput = "run.output"
	EventRunDone   = "run.finished"
	EventRunCancel = "run.cancel" // control event: the runner must stop the harness
	EventRunClose  = "run.close"  // control event: the runner closes the harness's input; the run ends when the harness does
	EventInput     = "input"
	EventFSRequest = "fs.request"   // data: FSRequest JSON (control plane → pod)
	EventFSResult  = "fs.result"    // data: FSResult JSON (pod → control plane)
	EventEgressOK  = "egress.allow" // data: Egress JSON
	EventEgressDen = "egress.deny"
	EventRollout   = "rollout" // data: Rollout JSON
)

// Instance is one issued agent identity: a certificate bound to one pod incarnation.
// Numbers are monotonic and never reused.
type Instance struct {
	N         int        `json:"n"`
	SandboxID string     `json:"sandbox_id"`
	Slug      string     `json:"slug"`
	Tenant    string     `json:"tenant"`
	PodName   string     `json:"pod_name"`
	Serial    string     `json:"serial"`
	IssuedAt  time.Time  `json:"issued_at"`
	NotAfter  time.Time  `json:"not_after"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
}
