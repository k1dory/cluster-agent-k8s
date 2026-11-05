// Package acpx is the platform's Agent Client Protocol client layer on top of
// github.com/coder/acp-go-sdk: ready calls for what the protocol and the agents we run offer
// beyond what the SDK (v0.13.5) types, so agent-runner speaks to every agent through one place.
//
// What it adds:
//
//   - Wire, a JSON-RPC level layer between the connection and the agent's stdio. It reads the
//     agent's capabilities the SDK drops from the initialize response (the client system prompt,
//     steering), advertises the client's session capabilities the SDK cannot express (live
//     notices, compaction updates), carries a session's system prompt, and hands over the session
//     updates the SDK silently zeroes (notice, compaction_update, compaction_summary_chunk).
//   - Conn: the SDK's client-side connection over a Wire, with Steer (_session/steering: a message
//     joins the turn in progress) and the agent's capabilities.
//   - Config options: select a session's mode, model or reasoning level by category (Configure),
//     matching the agent's own values.
//   - SessionMeta: a session request's _meta from the profile's free-form metadata and the system
//     prompt.
//
// Everything here is a client-side convenience over published ACP surfaces; when the SDK gains a
// field (systemPrompt, notices), the wire-level part of it can go.
package acpx
