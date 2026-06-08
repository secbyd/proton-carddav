package dav

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestOptionsHeader verifies that an OPTIONS request to the CardDAV server
// returns the mandatory DAV capability header advertising 'addressbook'.
func TestOptionsHeader(t *testing.T) {
	srv := NewServer("http://localhost", nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("OPTIONS status: want %d got %d", http.StatusNoContent, rr.Code)
	}
	dav := rr.Header().Get("DAV")
	if dav == "" {
		t.Fatal("OPTIONS response missing DAV header")
	}
	for _, token := range []string{"1", "2", "addressbook"} {
		found := false
		for _, v := range splitTokens(dav) {
			if v == token {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DAV header %q missing token %q", dav, token)
		}
	}
}

// TestUnknownMethodReturns405 verifies that unsupported HTTP methods
// are rejected with 405 Method Not Allowed.
func TestUnknownMethodReturns405(t *testing.T) {
	srv := NewServer("http://localhost", nil)

	for _, method := range []string{"POST", "PATCH", "TRACE"} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/", nil)
		srv.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: want 405 got %d", method, rr.Code)
		}
	}
}

// TestGetUnknownPathReturns404 verifies that a GET for an unknown resource
// returns 404.
func TestGetUnknownPathReturns404(t *testing.T) {
	srv := NewServer("http://localhost", nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/does/not/exist.vcf", nil)
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("GET unknown path: want 404 got %d", rr.Code)
	}
}

// splitTokens splits a comma-separated DAV header value into trimmed tokens.
func splitTokens(s string) []string {
	var out []string
	for _, t := range splitComma(s) {
		out = append(out, trimSpace(t))
	}
	return out
}

func splitComma(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
