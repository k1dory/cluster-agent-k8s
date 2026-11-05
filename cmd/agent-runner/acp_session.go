package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	acp "github.com/coder/acp-go-sdk"

	"github.com/k1dory/acpx"
)

// acpSessionState is what the agent said about a session when it opened.
type acpSessionState = acpx.SessionState

// acpResumer is session/resume (an agent that declares sessionCapabilities.resume): the
// session continues without its history being replayed.
type acpResumer interface {
	ResumeSession(ctx context.Context, params acp.ResumeSessionRequest) (acp.ResumeSessionResponse, error)
}

// acpSettings are the profile's choices for a session: harness.mode (HARNESS_MODE), the model
// (SANDBOX_MODEL) and harness.thought_level (HARNESS_THOUGHT_LEVEL).
type acpSettings struct {
	mode, model, thoughtLevel string
}

// The settings under the profile's names, for the run's notices.
var (
	modeSetting         = named(acpx.ModeSetting, "harness.mode")
	thoughtLevelSetting = named(acpx.ThoughtLevelSetting, "harness.thought_level")
)

func named(s acpx.Setting, name string) acpx.Setting {
	s.Name = name
	return s
}

// configureACPSession puts a freshly opened, loaded or resumed session in the profile's mode, on
// its model and its reasoning level, through what the agent advertised (acpx.Configure). What
// cannot be applied is reported, never fatal: the agent runs with its own default.
func configureACPSession(ctx context.Context, conn acpConn, sid acp.SessionId, st acpSessionState, s acpSettings, notice func(string, ...any)) {
	if s.mode == "" && s.model == "" && s.thoughtLevel == "" {
		return
	}
	cf, ok := conn.(acpx.Configurer)
	if !ok {
		notice("the connection cannot configure the session: harness.mode, the model and the thought level are left to the agent")
		return
	}
	for _, c := range []struct {
		setting acpx.Setting
		want    string
	}{{modeSetting, s.mode}, {acpx.ModelSetting, s.model}, {thoughtLevelSetting, s.thoughtLevel}} {
		if err := acpx.Configure(ctx, cf, sid, st, c.setting, c.want); err != nil {
			notice("%v", err)
		}
	}
}

// profileSessionMeta is harness.session_meta (HARNESS_SESSION_META, a JSON object): metadata
// every session request carries, e.g. claude-agent-acp's claudeCode.options.
func profileSessionMeta(raw string) (map[string]any, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return nil, fmt.Errorf("HARNESS_SESSION_META: %w", err)
	}
	return meta, nil
}

func noticeFunc(emit func(string)) func(string, ...any) {
	return func(format string, a ...any) { emit("[agent-runner] " + fmt.Sprintf(format, a...)) }
}
