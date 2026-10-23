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

// Run is one task handed to the agent inside a sandbox.
type Run struct {
	ID         string     `json:"id"`
	SandboxID  string     `json:"sandbox_id"`
	Task       string     `json:"task"`
	Status     RunStatus  `json:"status"`
	ExitCode   int        `json:"exit_code"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// Event is one line of the sandbox event stream (agent output, status changes).
type Event struct {
	ID        int64     `json:"id"`
	SandboxID string    `json:"sandbox_id"`
	RunID     string    `json:"run_id,omitempty"`
	Type      string    `json:"type"`
	Data      string    `json:"data,omitempty"`
	At        time.Time `json:"at"`
}

// Event types.
const (
	EventStatus    = "status"
	EventRunQueued = "run.queued"
	EventRunStart  = "run.started"
	EventRunOutput = "run.output"
	EventRunDone   = "run.finished"
	EventInput     = "input"
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
