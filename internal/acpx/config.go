package acpx

import (
	"context"
	"fmt"
	"slices"
	"strings"

	acp "github.com/coder/acp-go-sdk"
)

// SessionState is what the agent said about a session when it opened (new, load, resume): its
// modes and its configuration options. Either may be absent.
type SessionState struct {
	Modes   *acp.SessionModeState
	Options []acp.SessionConfigOption
}

// Configurer is what changing a session's configuration needs of a connection.
type Configurer interface {
	SetSessionMode(ctx context.Context, params acp.SetSessionModeRequest) (acp.SetSessionModeResponse, error)
	SetSessionConfigOption(ctx context.Context, params acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error)
}

// Setting names what to select and how a wanted value matches the agent's own.
type Setting struct {
	Name     string                          // for messages: "harness.mode", "model"…
	Category acp.SessionConfigOptionCategory // mode, model, thought_level
	// Modes: fall back to the session's modes (session/set_mode) when the agent has no config
	// option of the category. Only for the mode.
	Modes bool
	// Match picks the agent's value for want among its options; nil: the value itself.
	Match func(options []acp.SessionConfigSelectOption, want string) string
}

// The settings a profile can make.
var (
	ModeSetting = Setting{Name: "harness.mode", Category: acp.SessionConfigOptionCategoryMode, Modes: true}
	// ModelSetting matches the model's name, a provider-qualified value (OpenCode's
	// anthropic/claude-…) or an option of that display name.
	ModelSetting = Setting{Name: "model", Category: acp.SessionConfigOptionCategoryModel, Match: MatchModel}
	// ThoughtLevelSetting is the reasoning level (codex-acp reasoning_effort, OpenCode effort,
	// Hermes reasoning_effort): its value or display name.
	ThoughtLevelSetting = Setting{Name: "harness.thought_level", Category: acp.SessionConfigOptionCategoryThoughtLevel, Match: MatchValueOrName}
)

// Configure selects want for the setting in a session. It changes nothing when the session already
// has it; what cannot be applied (no such option, a value the agent does not offer, a refusal) is
// returned as an error to report, and the session keeps the agent's own value.
func Configure(ctx context.Context, cf Configurer, sid acp.SessionId, st SessionState, s Setting, want string) error {
	if want == "" {
		return nil
	}
	if opt := ConfigOption(st.Options, s.Category); opt != nil {
		value := want
		if s.Match != nil {
			value = s.Match(SelectOptions(opt), want)
		} else if !slices.Contains(SelectValues(opt), want) {
			value = ""
		}
		if value == "" {
			return fmt.Errorf("%s %q is not one the agent offers %v: it stays %q", s.Name, want, abbreviate(SelectValues(opt)), opt.CurrentValue)
		}
		if string(opt.CurrentValue) == value {
			return nil
		}
		if _, err := cf.SetSessionConfigOption(ctx, acp.SetSessionConfigOptionRequest{ValueId: &acp.SetSessionConfigOptionValueId{
			SessionId: sid, ConfigId: opt.Id, Value: acp.SessionConfigValueId(value)}}); err != nil {
			return fmt.Errorf("acp session/set_config_option %s=%s: %w", opt.Id, value, err)
		}
		return nil
	}
	if !s.Modes {
		return fmt.Errorf("the agent offers no %s option: %s %q is left to its configuration", s.Category, s.Name, want)
	}
	if st.Modes == nil || len(st.Modes.AvailableModes) == 0 {
		return fmt.Errorf("the agent declares no session modes: %s %q is not applied", s.Name, want)
	}
	var ids []string
	for _, m := range st.Modes.AvailableModes {
		ids = append(ids, string(m.Id))
	}
	if !slices.Contains(ids, want) {
		return fmt.Errorf("%s %q is not a mode the agent offers %v: the agent stays in %q", s.Name, want, ids, st.Modes.CurrentModeId)
	}
	if string(st.Modes.CurrentModeId) == want {
		return nil
	}
	if _, err := cf.SetSessionMode(ctx, acp.SetSessionModeRequest{SessionId: sid, ModeId: acp.SessionModeId(want)}); err != nil {
		return fmt.Errorf("acp session/set_mode %s: %w", want, err)
	}
	return nil
}

// ConfigOption is the first select option of the category, nil when there is none.
func ConfigOption(options []acp.SessionConfigOption, cat acp.SessionConfigOptionCategory) *acp.SessionConfigOptionSelect {
	for _, o := range options {
		if s := o.Select; s != nil && s.Category != nil && *s.Category == cat {
			return s
		}
	}
	return nil
}

// SelectOptions lists a select option's values, grouped or not.
func SelectOptions(opt *acp.SessionConfigOptionSelect) []acp.SessionConfigSelectOption {
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

// SelectValues lists a select option's value ids.
func SelectValues(opt *acp.SessionConfigOptionSelect) []string {
	var out []string
	for _, o := range SelectOptions(opt) {
		out = append(out, string(o.Value))
	}
	return out
}

// MatchModel picks the value that is the model's name, else one that ends in /<name>, else one
// whose display name is it.
func MatchModel(options []acp.SessionConfigSelectOption, model string) string {
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

// MatchValueOrName picks the value that is want, else one whose display name is it.
func MatchValueOrName(options []acp.SessionConfigSelectOption, want string) string {
	for _, o := range options {
		if string(o.Value) == want {
			return want
		}
	}
	for _, o := range options {
		if strings.EqualFold(o.Name, want) {
			return string(o.Value)
		}
	}
	return ""
}

func abbreviate(values []string) []string {
	if len(values) > 12 {
		return append(values[:12:12], "…")
	}
	return values
}
