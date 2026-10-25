package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRejectsMissingSecretAndLegacyPolicies(t *testing.T) {
	for _, body := range []string{`{}`, `{"secret":"bad"}`, `{"secret":"` + testSecret + `","Channel":{}}`, `{"secret":"` + testSecret + `","enforce":false}`, `{"secret":"` + testSecret + `","domain":"example.com"}`, `{"secret":"` + testSecret + `"} {}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfig(path); err == nil {
			t.Errorf("invalid configuration accepted: %s", body)
		}
	}
}

func TestLoadConfigRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"secret":"` + testSecret + `"}` + strings.Repeat(" ", 64*1024) + ` {"enforce":false}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("oversized config accepted with hidden trailing input")
	}
}

func TestLoadConfigDefaultsAndNormalizesSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"secret":" jbswy3dpehpk3pxpjbswy3dpehpk3pxp "}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Secret != testSecret || cfg.BindAddress != "127.0.0.1:9000" {
		t.Fatalf("unexpected config: %s", cfg.BindAddress)
	}
}
