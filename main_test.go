package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
)

func TestCLIRejectsPositionalStart(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"start", "-c", "missing.json"}, &out, &out); err == nil {
		t.Fatal("unsupported start command accepted")
	}
}

func TestGenerateKeyWithoutConfig(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-e", "key", "-c", "missing.json"}, &out, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	key, err := otp.NewKeyFromURL(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	if key.Algorithm() != otp.AlgorithmSHA512 || key.Period() != 30 || key.Digits() != otp.DigitsSix {
		t.Fatal("generated key does not match verification settings")
	}
	cfg := Config{Secret: key.Secret()}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRunReturnsBindErrorPromptly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s, err := NewServer(&Config{BindAddress: listener.Addr().String(), Secret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	if err := s.Run(ctx); err == nil {
		t.Fatal("occupied port accepted")
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("bind error blocked until cancellation")
	}
}
