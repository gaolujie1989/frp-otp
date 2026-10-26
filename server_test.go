package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const testSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

func testServer(t *testing.T) *Server {
	t.Helper()
	var cfg Config
	if err := json.Unmarshal([]byte(`{"BindAddress":"127.0.0.1:0","secret":"`+testSecret+`"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func perform(s *Server, method, path, peer, xff, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = peer
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	if path == "/knock" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func validCode(t *testing.T) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(testSecret, time.Now(), totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA512})
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{"code": {code}}.Encode()
}

func denied(t *testing.T, s *Server, ip string) bool {
	t.Helper()
	body := fmt.Sprintf(`{"version":"0.1.0","op":"NewUserConn","content":{"proxy_name":"any-proxy","proxy_type":"tcp","remote_addr":"%s"}}`, ip)
	w := perform(s, "POST", "/handler", "127.0.0.1:5000", "", body)
	if w.Code != 200 {
		t.Fatalf("RPC status %d: %s", w.Code, w.Body.String())
	}
	var response struct {
		Reject   bool `json:"reject"`
		Unchange bool `json:"unchange"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Reject && !response.Unchange {
		t.Fatal("allow response must preserve original content")
	}
	return response.Reject
}

func TestUnauthorizedVisitorsDenied(t *testing.T) {
	s := testServer(t)
	for _, ip := range []string{"198.51.100.10:1234", "172.16.0.1:1234", "[2001:db8::1]:1234"} {
		if !denied(t, s, ip) {
			t.Errorf("unauthorized visitor %s allowed", ip)
		}
	}
}

func TestGlobalGrantAndIPIsolation(t *testing.T) {
	s := testServer(t)
	w := perform(s, "POST", "/knock", "198.51.100.10:1234", "", validCode(t))
	if w.Code != 200 {
		t.Fatalf("grant status %d", w.Code)
	}
	if denied(t, s, "198.51.100.10:4321") {
		t.Fatal("authorized IP rejected")
	}
	if !denied(t, s, "198.51.100.11:4321") {
		t.Fatal("different IP inherited grant")
	}
}

func TestForwardedIPTrustBoundary(t *testing.T) {
	for _, tc := range []struct{ name, peer, xff, want string }{
		{"private proxy", "192.168.1.2:1234", "198.51.100.10", "198.51.100.10:1"},
		{"ten network", "10.0.0.2:1234", "198.51.100.10", "198.51.100.10:1"},
		{"docker proxy", "172.20.0.2:1234", "198.51.100.10", "198.51.100.10:1"},
		{"ignore forged header", "198.51.100.10:1234", "203.0.113.99", "198.51.100.10:1"},
		{"ignore spoofed leftmost", "10.0.0.2:1234", "203.0.113.99, 198.51.100.10", "198.51.100.10:1"},
		{"internal proxy chain", "10.0.0.2:1234", "203.0.113.99, 198.51.100.10, 192.168.1.1", "198.51.100.10:1"},
		{"IPv6 proxy", "[fd00::2]:1234", "2001:db8::10", "[2001:db8::10]:1"},
		{"mapped IPv4", "[::ffff:192.168.1.2]:1234", "::ffff:198.51.100.10", "198.51.100.10:1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			w := perform(s, "POST", "/knock", tc.peer, tc.xff, validCode(t))
			if w.Code != 200 {
				t.Fatalf("grant status %d: %s", w.Code, w.Body.String())
			}
			if denied(t, s, tc.want) {
				t.Fatalf("expected grant for %s", tc.want)
			}
			if !denied(t, s, "203.0.113.99:1") {
				t.Fatal("spoofed address allowed")
			}
		})
	}
}

func TestInvalidForwardedIPRejected(t *testing.T) {
	for _, xff := range []string{"not-an-IP", "198.51.100.10, garbage", "198.51.100.10,", "198.51.100.10:1234"} {
		s := testServer(t)
		w := perform(s, "POST", "/knock", "10.0.0.2:1234", xff, validCode(t))
		if w.Code != 400 {
			t.Errorf("XFF %q status %d, want 400", xff, w.Code)
		}
	}
}

func TestOTPFailureDoesNotGrant(t *testing.T) {
	s := testServer(t)
	w := perform(s, "POST", "/knock", "198.51.100.10:1234", "", "code=invalid")
	if w.Code != 401 {
		t.Errorf("wrong OTP status %d, want 401", w.Code)
	}
	if !denied(t, s, "198.51.100.10:1") {
		t.Fatal("wrong OTP granted access")
	}
	w = perform(s, "POST", "/knock", "198.51.100.10:1234", "", validCode(t))
	if w.Code != 200 || denied(t, s, "198.51.100.10:1") {
		t.Fatal("correct OTP after one failure must authorize")
	}
}

func TestOTPAttemptLimit(t *testing.T) {
	s := testServer(t)
	for i := 0; i < 5; i++ {
		perform(s, "POST", "/knock", "198.51.100.10:1234", "", "code=invalid")
	}
	w := perform(s, "POST", "/knock", "198.51.100.10:1234", "", validCode(t))
	if w.Code != 429 || !denied(t, s, "198.51.100.10:1") {
		t.Fatal("rate limited IP authorized")
	}
}

func TestRPCOnlyTrustedPeers(t *testing.T) {
	w := perform(testServer(t), "POST", "/handler", "198.51.100.10:1234", "127.0.0.1", `{"op":"NewUserConn"}`)
	if w.Code != 403 {
		t.Fatalf("public callback status %d, want 403", w.Code)
	}
}

func TestMalformedRPCRejected(t *testing.T) {
	for _, body := range []string{"", `{}`, `null`, `{"op":"NewUserConn","content":null}`, `{"op":"NewUserConn","content":{}}`, `{"op":"Bogus","content":{}}`, `{"op":"NewUserConn","content":{}} {}`} {
		w := perform(testServer(t), "POST", "/handler", "127.0.0.1:1234", "", body)
		if w.Code < 400 {
			t.Errorf("malformed RPC %s: status %d", body, w.Code)
		}
	}
}

func TestProxyRegistrationRejectsUnprotectedTypes(t *testing.T) {
	for _, typ := range []string{"tcp", "https", "stcp", "tcpmux", "http", "udp", "sudp", "xtcp", "unknown"} {
		body := fmt.Sprintf(`{"version":"0.1.0","op":"NewProxy","content":{"proxy_name":"any","proxy_type":"%s"}}`, typ)
		w := perform(testServer(t), "POST", "/handler", "127.0.0.1:1234", "", body)
		var res struct {
			Reject bool `json:"reject"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		want := typ == "http" || typ == "udp" || typ == "sudp" || typ == "xtcp" || typ == "unknown"
		if res.Reject != want {
			t.Errorf("%s reject=%v want %v", typ, res.Reject, want)
		}
	}
}

func TestGrantExpiresAndCleanupRetainsActiveClients(t *testing.T) {
	s := testServer(t)
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	code, err := totp.GenerateCodeCustom(testSecret, now, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA512})
	if err != nil {
		t.Fatal(err)
	}
	if w := perform(s, "POST", "/knock", "198.51.100.10:1234", "", url.Values{"code": {code}}.Encode()); w.Code != 200 {
		t.Fatal(w.Code)
	}
	now = now.Add(4*time.Hour - time.Second)
	s.mu.Lock()
	s.cleanup(now)
	s.mu.Unlock()
	if denied(t, s, "198.51.100.10:1") {
		t.Fatal("grant expired early")
	}
	now = now.Add(time.Second)
	if !denied(t, s, "198.51.100.10:1") {
		t.Fatal("grant still valid at four-hour boundary")
	}
	s.mu.Lock()
	s.cleanup(now)
	remaining := len(s.clients)
	s.mu.Unlock()
	if remaining != 0 {
		t.Fatal("expired state was not cleaned")
	}
}

func TestTrustDefaultsAndOverrides(t *testing.T) {
	for _, tc := range []struct {
		name, extra       string
		allowed, rejected []string
	}{
		{"defaults", "", []string{"10.0.0.0:1", "10.255.255.255:1", "192.168.0.0:1", "192.168.255.255:1", "[::ffff:10.1.2.3]:1"}, []string{"9.255.255.255:1", "11.0.0.0:1", "192.167.255.255:1", "192.169.0.0:1", "172.16.0.1:1", "127.0.0.1:1", "[fd00::1]:1", "198.51.100.1:1"}},
		{"disabled", `,"trust_networks":[]`, nil, []string{"10.1.2.3:1", "192.168.1.2:1"}},
		{"null defaults", `,"trust_networks":null`, []string{"10.1.2.3:1", "192.168.1.2:1"}, []string{"172.20.1.2:1"}},
		{"mapped CIDR", `,"trust_networks":["::ffff:10.0.0.0/104"]`, []string{"10.1.2.3:1", "[::ffff:10.1.2.3]:1"}, []string{"192.168.1.2:1"}},
		{"custom", `,"trust_networks":["172.20.0.0/16","fd12:3456::/32"]`, []string{"172.20.1.2:1", "[fd12:3456::1]:1"}, []string{"172.21.1.2:1", "10.1.2.3:1", "192.168.1.2:1", "[fd12:3457::1]:1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewServer(loadTestConfig(t, tc.extra))
			if err != nil {
				t.Fatal(err)
			}
			for _, ip := range tc.allowed {
				if denied(t, s, ip) {
					t.Errorf("trusted visitor %s rejected", ip)
				}
			}
			for _, ip := range tc.rejected {
				if !denied(t, s, ip) {
					t.Errorf("untrusted visitor %s allowed", ip)
				}
			}
		})
	}
}

func TestConfiguredGrantDurationAndUI(t *testing.T) {
	s, err := NewServer(loadTestConfig(t, `,"grant_duration":"90m","trust_networks":[]`))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.now = func() time.Time { return now }
	form := perform(s, "GET", "/", "198.51.100.10:1", "", "")
	if !strings.Contains(form.Body.String(), "1h30m0s") {
		t.Fatal("form does not show configured duration")
	}
	w := perform(s, "POST", "/knock", "198.51.100.10:1", "", validCode(t))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "1h30m0s") {
		t.Fatalf("grant response: %d %s", w.Code, w.Body.String())
	}
	now = now.Add(90*time.Minute - time.Nanosecond)
	if denied(t, s, "198.51.100.10:1") {
		t.Fatal("configured grant expired early")
	}
	now = now.Add(time.Nanosecond)
	if !denied(t, s, "198.51.100.10:1") {
		t.Fatal("configured grant did not expire")
	}
}

func TestGrantWorksAcrossProxyNames(t *testing.T) {
	s := testServer(t)
	perform(s, "POST", "/knock", "198.51.100.10:1234", "", validCode(t))
	for _, name := range []string{"alice.ssh", "bob.rdp"} {
		body := fmt.Sprintf(`{"op":"NewUserConn","content":{"proxy_name":"%s","proxy_type":"tcp","remote_addr":"198.51.100.10:1"}}`, name)
		w := perform(s, "POST", "/handler", "127.0.0.1:1234", "", body)
		var res struct {
			Reject bool `json:"reject"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || res.Reject {
			t.Fatalf("global grant rejected for %s", name)
		}
	}
}

func TestGETCannotGrantAndOversizedBodiesRejected(t *testing.T) {
	s := testServer(t)
	perform(s, "GET", "/knock?"+validCode(t), "198.51.100.10:1234", "", "")
	if !denied(t, s, "198.51.100.10:1") {
		t.Fatal("GET request granted access")
	}
	w := perform(s, "POST", "/knock", "198.51.100.10:1234", "", "code="+strings.Repeat("1", maxBodyBytes))
	if w.Code != 400 {
		t.Fatal("oversized form accepted")
	}
	w = perform(s, "POST", "/handler", "127.0.0.1:1234", "", `{"op":"NewProxy","content":{"proxy_name":"`+strings.Repeat("a", maxBodyBytes)+`","proxy_type":"tcp"}}`)
	if w.Code != 400 {
		t.Fatal("oversized callback accepted")
	}
}

func TestMultipleForwardedHeaders(t *testing.T) {
	s := testServer(t)
	r := httptest.NewRequest("POST", "/knock", strings.NewReader(validCode(t)))
	r.RemoteAddr = "10.0.0.2:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("X-Forwarded-For", "203.0.113.99")
	r.Header.Add("X-Forwarded-For", "198.51.100.10, 192.168.1.1")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || denied(t, s, "198.51.100.10:1") || !denied(t, s, "203.0.113.99:1") {
		t.Fatal("multiple headers resolved incorrectly")
	}
}

func TestAuthorizationStateBounded(t *testing.T) {
	s := testServer(t)
	now := s.now()
	s.mu.Lock()
	for i := 0; i < maxTrackedIPs; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		s.clients[ip] = clientState{windowUntil: now.Add(time.Minute), failures: 1}
	}
	s.mu.Unlock()
	w := perform(s, "POST", "/knock", "198.51.100.10:1234", "", validCode(t))
	if w.Code != 429 {
		t.Fatal("state capacity exceeded")
	}
}
