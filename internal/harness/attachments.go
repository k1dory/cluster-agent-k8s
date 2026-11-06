package harness

import (
	"path"
	"strings"
	"unicode"
)

// attachmentsHeader opens the list of files a message has attached, after its text. It is the
// contract between the control plane, which writes it (every harness reads it as text), and the
// runner, which hands an ACP agent the files as resource links (SplitAttachments).
const attachmentsHeader = "\n\nAttached files:\n- "

// WithAttachments is a message's text with its attached files (absolute paths in the agent's
// file system) listed after it.
func WithAttachments(text string, paths []string) string {
	if len(paths) == 0 {
		return text
	}
	if strings.TrimSpace(text) == "" {
		text = "See the attached files."
	}
	return text + attachmentsHeader + strings.Join(paths, "\n- ")
}

// SplitAttachments takes WithAttachments apart: the text and the files. A text without the list
// is returned whole.
func SplitAttachments(s string) (text string, paths []string) {
	i := strings.LastIndex(s, attachmentsHeader)
	if i < 0 {
		return s, nil
	}
	for _, l := range strings.Split(s[i+len(attachmentsHeader):], "\n- ") {
		l = strings.TrimSpace(l)
		if !AttachmentPath(l) {
			return s, nil // not the list the control plane writes: text
		}
		paths = append(paths, l)
	}
	return s[:i], paths
}

// AttachmentPath is a path the attachment list may hold: in the workspace, clean, no control
// characters (which could start a line of the list).
func AttachmentPath(p string) bool {
	if !strings.HasPrefix(p, "/workspace/") || path.Clean(p) != p || strings.ContainsFunc(p, unicode.IsControl) {
		return false
	}
	return true
}
