# OTP form usability implementation plan

> Execute directly in this session using superpowers:executing-plans as authorized by the user.

**Goal:** Enlarge OTP controls, allow validated clipboard input, and retain the form above which submission results appear.

**Architecture:** Keep the existing Go HTTP service and native POST form. Render GET and POST responses through one escaped HTML template; inline JavaScript only handles clipboard reads. No frontend framework or new runtime dependency.

**Design:** The input is full width with a minimum height of 56px and 24px text. Both buttons have a minimum height of 48px and 18px text, with a narrow-screen layout that does not overflow. The new “读取剪贴板” button reads only on a click, trims surrounding whitespace, and fills only six ASCII digits, preserving leading zeros. Invalid content, unavailable API, insecure context, and permission denial produce a visible message without replacing the existing input. Reading never submits. A single accessible status region sits above the form. POST success, invalid code, rate limiting, malformed form, and invalid client address all render the same form with a message. Preserve status codes, rate limit headers, configurable grant duration, and authorization behavior. Do not echo submitted OTPs.

**Approach:** Server-rendered result pages reuse the existing POST flow and work without JavaScript. AJAX submission would add network/error state without helping the requested behavior, so it is unnecessary. Clipboard reads require browser support and usually HTTPS or localhost; retain manual typing/paste and explain failures in the page.

## Execution order

- [x] User explicitly requested skipping the issue; proceed directly to code and PR.
- [x] Create an isolated feature branch based on `main`.
- [x] Add focused response regressions covering GET, successful POST, invalid OTP, rate limiting with `Retry-After`, invalid client IP, and malformed/oversized POST: each response must contain an HTML form and the result region before it.
- [x] Implement a reusable escaped HTML template and render helper; enlarge controls and add clipboard-only JavaScript with six-digit validation and informative failure messages.
- [x] Check clipboard behavior for `012345`, surrounding whitespace, empty text, 5/7 digits, mixed text, embedded newlines, denied permissions, and unsupported HTTP context. Invalid reads preserve existing input and never authorize.
- [x] Run Go tests with the race detector, vet, and build if the declared Go toolchain is available; verify mobile/desktop layout and clipboard behavior with the available browser tooling. Record unavailable checks explicitly.
- [ ] Review diff, push the feature branch, and create a PR targeting this repository's `main` with actual validation results.

## Review focus

- Leading zeros survive clipboard filling.
- Clipboard failures retain manual input and the form.
- Submit success and errors retain the form and current HTTP semantics.
- User-controlled strings are escaped in rendered HTML.
- Controls fit a 320px viewport and support keyboard use.

## Current constraints

- Repository: `gaolujie1989/frp-otp`; base SHA: `e6cbc13359df04d666000afd79389bbd74048181`.
- Relevant code: `server.go`, `server_test.go`; a dedicated `page.go` may hold the template/render helper to keep the handler readable.
- No repository `AGENTS.md` was found.
- Installed the exact Go 1.27.3 declared by `go.mod` into a task-local tool directory for verification.
- Browser installation returned invalid download archives, so visual QA is unavailable; clipboard behavior is covered by execution of the actual inline script in Node with a browser-boundary test harness.

## Verification results

- `go test -race ./...`: passed (24 top-level tests).
- `go vet ./...`: passed.
- `make build`: passed using Go 1.27.3.
- `node --test scripts/page.test.cjs`: 4/4 passed.
- `git diff --check`: passed.
- Browser visual QA unavailable because browser download archives were invalid.
- Docker is unavailable locally; its build remains covered by the existing CI job.
