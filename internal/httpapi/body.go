package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"

	"agent-sandbox/internal/orchestrator"
)

// Request bodies follow one policy, chosen by the class of the route. Every body is read
// through http.MaxBytesReader at its class's cap, so nothing is read without a bound and
// nothing is silently cut: a body over the cap is 413, a malformed one 400, both in the error
// envelope. The idempotency middleware reads under the same cap, so the hash it stores is
// always over the whole body the handler sees.
const (
	// jsonBodyLimit bounds the JSON bodies of the sandbox, run, message, preview, rollout and
	// rollback routes: a task or a message text and a few fields.
	jsonBodyLimit = 1 << 20
	// smallBodyLimit bounds the JSON bodies that carry a few short fields (keys, rotation).
	smallBodyLimit = 1 << 16
	// documentBodyLimit bounds one versioned document (PUT /v1/<kind>/{name}).
	documentBodyLimit = 1 << 20
	// bundleBodyLimit bounds a plan or apply bundle (many documents).
	bundleBodyLimit = 8 << 20
	// MaxUploadFiles is how many files one multipart message may carry.
	MaxUploadFiles = 8
	// multipartBodyLimit is a whole multipart message: every file at its cap, plus room for
	// the text field, the part headers and the boundaries. It also bounds what
	// ParseMultipartForm can spill to temporary files.
	multipartBodyLimit = MaxUploadFiles*orchestrator.MaxFileBytes + 1<<20
	// multipartMemory is what ParseMultipartForm keeps in memory; larger files go to disk.
	multipartMemory = 8 << 20
)

// isMultipart reports whether the request carries multipart/form-data.
func isMultipart(r *http.Request) bool {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return ct == "multipart/form-data"
}

// messageBodyLimit is the cap of POST /messages: multipart with files, or JSON.
func messageBodyLimit(r *http.Request) int64 {
	if isMultipart(r) {
		return multipartBodyLimit
	}
	return jsonBodyLimit
}

// capBody puts the request body under limit bytes. Capping twice is harmless: the smaller
// cap wins.
func capBody(w http.ResponseWriter, r *http.Request, limit int64) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
}

// bodyTooLarge reports whether err comes from a body over its cap.
func bodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe) || errors.Is(err, multipart.ErrMessageTooLarge)
}

// writeBodyErr answers a body that could not be read or decoded: 413 when it is over its cap,
// 400 otherwise.
func writeBodyErr(w http.ResponseWriter, err error) {
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("body: exceeds %d bytes", mbe.Limit))
	case bodyTooLarge(err):
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("body: %w", err))
	default:
		writeErr(w, http.StatusBadRequest, err)
	}
}

// readBody reads the whole body under limit; the error goes to writeBodyErr.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	capBody(w, r, limit)
	return io.ReadAll(r.Body)
}

// decodeJSON is decodeStrict at the JSON class's cap: the body of every small JSON route.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	return decodeStrict(w, r, v, jsonBodyLimit)
}

// decodeStrict reads exactly one JSON object of at most limit bytes into v: a body that is
// not an object (null, a string, an array), unknown fields, a second document or trailing
// garbage after the object are errors, so nothing is written on a body that was not what the
// client meant to send. The stream is read to its end before the object is decoded.
func decodeStrict(w http.ResponseWriter, r *http.Request, v any, limit int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("body: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if bodyTooLarge(err) {
			return fmt.Errorf("body: %w", err)
		}
		return errors.New("body: trailing data after the JSON object")
	}
	if b := bytes.TrimSpace(raw); len(b) == 0 || b[0] != '{' {
		return errors.New("body: one JSON object is expected")
	}
	obj := json.NewDecoder(bytes.NewReader(raw))
	obj.DisallowUnknownFields()
	if err := obj.Decode(v); err != nil {
		return fmt.Errorf("body: %w", err)
	}
	return nil
}

// removeForm deletes the temporary files of a parsed multipart form once the route is done,
// whatever way it ends (an answer, a replay, a refusal). net/http removes them only for the
// request it created, and auth hands the handlers a copy (WithContext), so its cleanup never
// sees the form parsed here.
func removeForm(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
		}()
		next(w, r)
	}
}
