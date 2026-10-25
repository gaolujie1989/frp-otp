package main

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// Config contains only the HTTP listener and the shared TOTP secret.
type Config struct {
	BindAddress string `json:"BindAddress"`
	Secret      string `json:"secret"`
}

func (c *Config) validate() error {
	if c.BindAddress == "" {
		c.BindAddress = "127.0.0.1:9000"
	}
	if _, _, err := net.SplitHostPort(c.BindAddress); err != nil {
		return fmt.Errorf("invalid BindAddress: %w", err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(c.Secret)
	if err != nil || len(secret) < 20 {
		return errors.New("secret must be a base32 TOTP secret of at least 20 bytes; generate one with -e key")
	}
	return nil
}

func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64*1024 {
		return nil, errors.New("configuration exceeds 64 KiB")
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("config must contain one JSON object")
	}
	cfg.Secret = strings.ToUpper(strings.TrimSpace(cfg.Secret))
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
