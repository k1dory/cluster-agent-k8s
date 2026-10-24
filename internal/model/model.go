// Package model holds the data types shared by the store, orchestrator and API.
package model

import "time"

// SandboxStatus is the lifecycle state of a sandbox.
type SandboxStatus string

const (
	StatusCreating SandboxStatus = "creating"
	StatusRunning  SandboxStatus = "running"
	StatusSleeping SandboxStatus = "sleeping"
	StatusWaking   SandboxStatus = "waking"
	StatusStopping SandboxStatus = "stopping"
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

// Sandbox is one agent workspace: a persistent volume plus, while awake, one pod.
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
	LastActivity  time.Time     `json:"last_activity"`
	CreatedAt     time.Time     `json:"created_at"`
	Preview       *Preview      `json:"preview,omitempty"`
	Error         string        `json:"error,omitempty"`
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
	ID         string     `json:"id"`
	SandboxID  string     `json:"sandbox_id"`
	Tenant     string     `json:"tenant,omitempty"`
	Slug       string     `json:"slug,omitempty"`
	Task       string     `json:"task"`
	Status     RunStatus  `json:"status"`
	ExitCode   int        `json:"exit_code"`
	Usage      Usage      `json:"usage"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

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

// Event types.
const (
	EventStatus    = "status"
	EventRunQueued = "run.queued"
	EventRunStart  = "run.started"
	EventRunOutput = "run.output"
	EventRunDone   = "run.finished"
	EventRunCancel = "run.cancel" // control event: the runner must stop the harness
	EventInput     = "input"
	EventEgressOK  = "egress.allow" // data: Egress JSON
	EventEgressDen = "egress.deny"
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
