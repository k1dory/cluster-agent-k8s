package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadConfig(t *testing.T, body string) (*Config, error) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "sandboxd.yaml")
	if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(f)
}

// Defaults: metrics on :9090, tracing off at ratio 1; "" turns the metrics listener off.
func TestObservabilityDefaults(t *testing.T) {
	c, err := loadConfig(t, "runtime: fake\n")
	if err != nil {
		t.Fatal(err)
	}
	if *c.Metrics.Listen != ":9090" || c.Tracing.Enabled || *c.Tracing.SamplerRatio != 1 || c.Tracing.RecordStatements {
		t.Fatalf("defaults: metrics %q tracing %+v", *c.Metrics.Listen, c.Tracing)
	}
	c, err = loadConfig(t, "runtime: fake\nmetrics:\n  listen: \"\"\ntracing:\n  enabled: true\n  endpoint: http://tempo:4318\n  protocol: grpc\n  sampler_ratio: 0.25\n")
	if err != nil {
		t.Fatal(err)
	}
	if *c.Metrics.Listen != "" || !c.Tracing.Enabled || c.Tracing.Protocol != "grpc" || *c.Tracing.SamplerRatio != 0.25 {
		t.Fatalf("explicit: metrics %q tracing %+v", *c.Metrics.Listen, c.Tracing)
	}
}

func TestObservabilityIsValidated(t *testing.T) {
	for body, want := range map[string]string{
		"metrics:\n  listen: \":8080\"\n":                                             "listen.api",            // /metrics on the API port
		"listen:\n  gateway: 127.0.0.1:9090\n":                                        "listen.gateway",        // the default collides
		"metrics:\n  listen: nonsense\n":                                              "metrics.listen",        //
		"tracing:\n  sampler_ratio: 1.5\n":                                            "tracing.sampler_ratio", //
		"tracing:\n  sampler_ratio: -0.1\n":                                           "tracing.sampler_ratio", //
		"tracing:\n  protocol: zipkin\n":                                              "tracing.protocol",      //
		"tracing:\n  endpoint: tempo:4318\n":                                          "tracing.endpoint",      // no scheme
		"tracing:\n  endpoint: \"ftp://x\"\n":                                         "tracing.endpoint",      //
		"metrics:\n  listen: \"127.0.0.1:9100\"\nlisten:\n  api: \"10.0.0.1:9100\"\n": "",
	} {
		_, err := loadConfig(t, "runtime: fake\n"+body)
		if want == "" {
			if err != nil {
				t.Errorf("%q: %v", body, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want one naming %s", body, err, want)
		}
	}
}
