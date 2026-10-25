# Minimal global IP allowlist implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan in this session.

**Goal:** Replace channel policies with one OTP-protected, five-minute global IP allowlist.

**Architecture:** Keep the standalone Go HTTP service and the frps HTTP plugin protocol. Trust forwarded addresses only from private or loopback immediate peers. Resolve X-Forwarded-For from right to left to the nearest untrusted address. Private addresses are trusted proxy peers, not automatically authorized visitors.

**Tech Stack:** Go 1.27.3, frp v0.71.1, pquerna/otp v1.5.0.

**Spec:** User requirements in this conversation, 2026-10-25: minimal functionality, no domain or channel management, deny visitors by default, authorize IPs after OTP, trust XFF only from internal peers, correct startup, updated dependencies.

## Global Constraints
- One secret; retain SHA-512 TOTP compatibility and fixed five-minute grants.
- No permanent whitelist, channel policies, bypass, notification, database, embedded TLS or domain configuration.
- Only NewProxy and NewUserConn callbacks; reject registration of proxy types without meaningful connection admission (HTTP, UDP, SUDP, XTCP).
- Trust RFC1918, IPv6 ULA and loopback transport peers. Public immediate peers cannot override their IP with XFF.
- Keep grants in memory and clear expired entries periodically; bounded OTP failure state.
- Correct CLI: -e web / -e key; preserve -c and -v.

## Review Focus
- Spoofed XFF leftmost values, malformed entries, multiple header lines, mapped IPv4.
- Unauthorized private clients and unsupported protocols must not silently bypass admission.
- Expiration boundary, failed OTP followed by valid OTP, parallel requests.
- Invalid configuration, legacy fields and positional CLI arguments must fail visibly.
- Startup bind failure and termination must return promptly.

### Task 1: Global authorization and proxy admission
**Files:** config.go, server.go, server_test.go.
**Interfaces:** NewServer(*Config) (*Server,error); Server implements http.Handler; Config loaded from JSON.
- [x] Write black-box HTTP tests for default-deny, global grant, correct and incorrect OTP, trusted/untrusted proxy chains, private callback restriction, malformed RPC, unsupported protocols.
- [x] Run tests against old code and record expected failures.
- [x] Implement global store, bounded failures, trusted IP resolution, strict RPC parsing and small form page.
- [x] Run complete tests and race detector.

### Task 2: Configuration, lifecycle and packaging
**Files:** main.go, config_test.go, main_test.go, go.mod, go.sum, Dockerfile, Makefile, frp.otp.json, README.md, compose.yaml, examples/frps.toml.
**Interfaces:** run(args, stdout, stderr) error; loadConfig(path) (*Config,error); Server.Run(context.Context) error.
- [x] Write tests for invalid/legacy configuration, command parsing, secret generation and bind failures; observe failures before fixes.
- [x] Update dependencies; fix CLI, shutdown and periodic cleanup; simplify packaging and documentation.
- [x] Run go test -race ./..., go vet ./..., make build and executable smoke checks.
- [x] Review the entire change and address findings. Open a draft PR after final verification without merging or publishing.

## Verification and decisions
- Go tests and race detector, go vet, Makefile build and whitespace checks passed.
- Official frps/frpc v0.71.1 binaries: unauthorized TCP rejected; OTP grants apply across two proxies; private XFF grant matches remote_addr; graceful SIGTERM; plugin outage denies new connections.
- Independent review found no Critical/Important issues. Fixed its configuration-size truncation finding with a failing-then-passing regression test.
- Preserve repeatable TOTP validation within its valid time steps, as in the existing project; no extra token lifecycle.
- Private/loopback callback peers and right-to-left XFF trust are deliberate; deployment must restrict ingress to actual trusted proxies. Private clients are not automatically authorized.
- Reject unsupported proxy registrations rather than silently leaving them unprotected; changing subscriptions is documented.
- Docker is unavailable locally. The added CI builds the image; no image or release has been published.
