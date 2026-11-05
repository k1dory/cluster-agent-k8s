package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	acp "github.com/coder/acp-go-sdk"
)

// acpSessionState is what the agent said about a session when it opened: its modes and its
// configuration options (either may be absent).
type acpSessionState struct {
	modes   *acp.SessionModeState
	options []acp.SessionConfigOption
}

// acpConfigurer is what applying the profile to a session needs of the connection (the
// client-side connection has it; a scripted one in a test may not).
type acpConfigurer interface {
	SetSessionMode(ctx context.Context, params acp.SetSessionModeRequest) (acp.SetSessionModeResponse, error)
	SetSessionConfigOption(ctx context.Context, params acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error)
}

// acpResumer is session/resume (an agent that declares sessionCapabilities.resume): the
// session continues without its history being replayed.
type acpResumer interface {
	ResumeSession(ctx context.Context, params acp.ResumeSessionRequest) (acp.ResumeSessionResponse, error)
}

// configureACPSession puts a freshly opened, loaded or resumed session in the profile's mode
// (harness.mode → HARNESS_MODE) and on its model (SANDBOX_MODEL). Both go through what the
// agent advertised: a configuration option of the right category first (the newer ACP
// mechanism), then, for the mode, the session modes. What cannot be applied is reported,
// never fatal: the agent runs with its own default.
func configureACPSession(ctx context.Context, conn acpConn, sid acp.SessionId, st acpSessionState, mode, model string, notice func(string, ...any)) {
	if mode == "" && model == "" {
		return
	}
	cf, ok := conn.(acpConfigurer)
	if !ok {
		notice("the connection cannot configure the session: harness.mode and the model are left to the agent")
		return
	}
	if mode != "" {
		setACPMode(ctx, cf, sid, st, mode, notice)
	}
	if model != "" {
		setACPModel(ctx, cf, sid, st, model, notice)
	}
}

func setACPMode(ctx context.Context, cf acpConfigurer, sid acp.SessionId, st acpSessionState, mode string, notice func(string, ...any)) {
	if opt := configOption(st.options, acp.SessionConfigOptionCategoryMode); opt != nil {
		values := selectValues(opt)
		if !slices.Contains(values, mode) {
			notice("harness.mode %q is not a mode the agent offers %v: the agent stays in %q", mode, values, opt.CurrentValue)
			return
		}
		if string(opt.CurrentValue) == mode {
			return
		}
		if _, err := cf.SetSessionConfigOption(ctx, acp.SetSessionConfigOptionRequest{ValueId: &acp.SetSessionConfigOptionValueId{
			SessionId: sid, ConfigId: opt.Id, Value: acp.SessionConfigValueId(mode)}}); err != nil {
			notice("acp session/set_config_option %s=%s: %v", opt.Id, mode, err)
		}
		return
	}
	if st.modes == nil || len(st.modes.AvailableModes) == 0 {
		notice("the agent declares no session modes: harness.mode %q is not applied", mode)
		return
	}
	var ids []string
	for _, m := range st.modes.AvailableModes {
		ids = append(ids, string(m.Id))
	}
	if !slices.Contains(ids, mode) {
		notice("harness.mode %q is not a mode the agent offers %v: the agent stays in %q", mode, ids, st.modes.CurrentModeId)
		return
	}
	if string(st.modes.CurrentModeId) == mode {
		return
	}
	if _, err := cf.SetSessionMode(ctx, acp.SetSessionModeRequest{SessionId: sid, ModeId: acp.SessionModeId(mode)}); err != nil {
		notice("acp session/set_mode %s: %v", mode, err)
	}
}

// setACPModel selects the profile's model through the agent's model option. The option's value
// may be the model's name itself, a provider-qualified one (OpenCode's anthropic/claude-…) or
// an alias whose display name is the model's.
func setACPModel(ctx context.Context, cf acpConfigurer, sid acp.SessionId, st acpSessionState, model string, notice func(string, ...any)) {
	opt := configOption(st.options, acp.SessionConfigOptionCategoryModel)
	if opt == nil {
		notice("the agent offers no model option: the model %q is left to its configuration (SANDBOX_MODEL)", model)
		return
	}
	value := matchModel(opt, model)
	if value == "" {
		values := selectValues(opt)
		if len(values) > 12 {
			values = append(values[:12], "…")
		}
		notice("model %q is not one the agent offers %v: it stays on %q", model, values, opt.CurrentValue)
		return
	}
	if string(opt.CurrentValue) == value {
		return
	}
	if _, err := cf.SetSessionConfigOption(ctx, acp.SetSessionConfigOptionRequest{ValueId: &acp.SetSessionConfigOptionValueId{
		SessionId: sid, ConfigId: opt.Id, Value: acp.SessionConfigValueId(value)}}); err != nil {
		notice("acp session/set_config_option %s=%s: %v", opt.Id, value, err)
	}
}

// configOption is the first select option of the category, nil when there is none.
func configOption(options []acp.SessionConfigOption, cat acp.SessionConfigOptionCategory) *acp.SessionConfigOptionSelect {
	for _, o := range options {
		if s := o.Select; s != nil && s.Category != nil && *s.Category == cat {
			return s
		}
	}
	return nil
}

func selectOptions(opt *acp.SessionConfigOptionSelect) []acp.SessionConfigSelectOption {
	var out []acp.SessionConfigSelectOption
	if u := opt.Options.Ungrouped; u != nil {
		out = append(out, *u...)
	}
	if g := opt.Options.Grouped; g != nil {
		for _, group := range *g {
			out = append(out, group.Options...)
		}
	}
	return out
}

func selectValues(opt *acp.SessionConfigOptionSelect) []string {
	var out []string
	for _, o := range selectOptions(opt) {
		out = append(out, string(o.Value))
	}
	return out
}

func matchModel(opt *acp.SessionConfigOptionSelect, model string) string {
	options := selectOptions(opt)
	for _, match := range []func(acp.SessionConfigSelectOption) bool{
		func(o acp.SessionConfigSelectOption) bool { return string(o.Value) == model },
		func(o acp.SessionConfigSelectOption) bool { return strings.HasSuffix(string(o.Value), "/"+model) },
		func(o acp.SessionConfigSelectOption) bool { return strings.EqualFold(o.Name, model) },
	} {
		for _, o := range options {
			if match(o) {
				return string(o.Value)
			}
		}
	}
	return ""
}

// sessionMeta is the _meta of a session request: the system prompt marker when the agent
// takes one (acp_wire.go), nothing otherwise.
func sessionMeta(systemPrompt string) map[string]any {
	if systemPrompt == "" {
		return nil
	}
	return map[string]any{systemPromptMetaKey: systemPrompt}
}

func noticeFunc(emit func(string)) func(string, ...any) {
	return func(format string, a ...any) { emit("[agent-runner] " + fmt.Sprintf(format, a...)) }
}
