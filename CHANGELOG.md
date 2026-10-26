# Changelog

## Unreleased

- Make OTP grant duration configurable via `grant_duration`, defaulting to four hours.
- Add configurable `trust_networks` visitor CIDRs; default to 10.0.0.0/8 and 192.168.0.0/16, with an empty list disabling bypass.
- Validate access policy configuration and show the configured duration in the authorization UI.

## v0.1.0 - 2026-10-25

- Replace channel policies with a single five-minute global IP allowlist; deny visitors by default.
- Trust X-Forwarded-For only from private/loopback immediate peers and resolve proxy chains right to left.
- Fix OTP failure accounting, strict request/configuration parsing, cleanup, startup errors and graceful shutdown.
- Update Go to 1.27.3, frp to v0.71.1 and pquerna/otp to v1.5.0.
- Correct CLI, Makefile and non-root Docker packaging; add Compose and frps TOML examples.
