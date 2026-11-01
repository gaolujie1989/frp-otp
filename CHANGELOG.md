# Changelog

## v0.1.2 - 2026-11-01

- Enlarge OTP inputs and buttons with a responsive layout for mobile use.
- Add a clipboard button that accepts only six digits, preserves leading zeros, and reports invalid content or unavailable access.
- Keep the authorization form visible after submission and display success or failure above it.
- Add clipboard behavior and HTML response regression tests.

## v0.1.1 - 2026-10-26

- Make OTP grant duration configurable via `grant_duration`, defaulting to four hours.
- Add configurable `trust_networks` visitor CIDRs; default to 10.0.0.0/8 and 192.168.0.0/16, with an empty list disabling bypass.
- Validate access policy configuration and show the configured duration in the authorization UI.

## v0.1.0 - 2026-10-25

- Replace channel policies with a single five-minute global IP allowlist; deny visitors by default.
- Trust X-Forwarded-For only from private/loopback immediate peers and resolve proxy chains right to left.
- Fix OTP failure accounting, strict request/configuration parsing, cleanup, startup errors and graceful shutdown.
- Update Go to 1.27.3, frp to v0.71.1 and pquerna/otp to v1.5.0.
- Correct CLI, Makefile and non-root Docker packaging; add Compose and frps TOML examples.
