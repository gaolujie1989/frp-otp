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

func loadTestConfig(t *testing.T, extra string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"secret":"`+testSecret+`"`+extra+`}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestInvalidAccessPoliciesRejected(t *testing.T) {
	for _, extra := range []string{
		`,"grant_duration":"0s"`, `,"grant_duration":"-1h"`,
		`,"grant_duration":"tomorrow"`, `,"grant_duration":"999999999h"`,
		`,"trust_networks":["10.0/8"]`, `,"trust_networks":["not-a-network"]`,
		`,"trust_networks":["192.168.0.0/33"]`,
		`,"trust_networks":["::ffff:10.0.0.0/80"]`,
	} {
		t.Run(extra, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(`{"secret":"`+testSecret+`"`+extra+`}`), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatal("invalid access policy accepted")
			}
		})
	}
}
