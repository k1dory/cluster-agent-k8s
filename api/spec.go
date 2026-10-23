// Package api embeds the OpenAPI description served by sandboxd at /openapi.yaml.
package api

import _ "embed"

//go:embed openapi.yaml
var OpenAPI []byte
