package thoth

import "testing"

func TestApplyEnvFallbacksAPIURL(t *testing.T) {
	t.Setenv("THOTH_API_URL", "")
	if got := applyEnvFallbacks(Config{}).APIURL; got != "https://api.atensecurity.com" {
		t.Fatalf("no APIURL or THOTH_API_URL: got %q, want the trial and self-serve API", got)
	}

	t.Setenv("THOTH_API_URL", "https://enforce.acme.atensecurity.com")
	if got := applyEnvFallbacks(Config{}).APIURL; got != "https://enforce.acme.atensecurity.com" {
		t.Fatalf("THOTH_API_URL set: got %q", got)
	}

	cfg := Config{APIURL: "https://enforce.field.atensecurity.com"}
	if got := applyEnvFallbacks(cfg).APIURL; got != "https://enforce.field.atensecurity.com" {
		t.Fatalf("Config.APIURL set: got %q", got)
	}
}

func TestApplyEnvFallbacksAPIURLPrecedence(t *testing.T) {
	t.Setenv("THOTH_API_URL", "https://enforce.env.atensecurity.com")
	cfg := Config{APIURL: "https://enforce.field.atensecurity.com"}
	if got := applyEnvFallbacks(cfg).APIURL; got != "https://enforce.field.atensecurity.com" {
		t.Fatalf("Config.APIURL and THOTH_API_URL both set: got %q, want the Config value", got)
	}

	if got := applyEnvFallbacks(Config{APIURL: "  "}).APIURL; got != "https://enforce.env.atensecurity.com" {
		t.Fatalf("blank Config.APIURL: got %q, want THOTH_API_URL", got)
	}

	t.Setenv("THOTH_API_URL", "  ")
	if got := applyEnvFallbacks(Config{}).APIURL; got != "https://api.atensecurity.com" {
		t.Fatalf("blank Config.APIURL and THOTH_API_URL: got %q, want the default", got)
	}
}
