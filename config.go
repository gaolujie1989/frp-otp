package main

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Config contains the listener, TOTP secret and visitor access policy.
type Config struct {
	BindAddress   string   `json:"BindAddress"`
	Secret        string   `json:"secret"`
	GrantDuration string   `json:"grant_duration"`
	TrustNetworks []string `json:"trust_networks"`

	grantDuration time.Duration
	trustNetworks []netip.Prefix
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
	if c.GrantDuration == "" {
		c.GrantDuration = "4h"
	}
	duration, err := time.ParseDuration(c.GrantDuration)
	if err != nil || duration <= 0 {
		return errors.New("grant_duration must be a positive duration such as 4h or 30m")
	}
	c.grantDuration = duration
	if c.TrustNetworks == nil {
		c.TrustNetworks = []string{"10.0.0.0/8", "192.168.0.0/16"}
	}
	c.trustNetworks = make([]netip.Prefix, 0, len(c.TrustNetworks))
	for _, network := range c.TrustNetworks {
		prefix, err := netip.ParsePrefix(network)
		if err != nil {
			return fmt.Errorf("invalid trust_networks CIDR %q: %w", network, err)
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return fmt.Errorf("invalid trust_networks CIDR %q: mapped IPv4 prefix must be at least /96", network)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		c.trustNetworks = append(c.trustNetworks, prefix.Masked())
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
