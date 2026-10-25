package security

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matthogan/licenceserver/internal/config"
)

func TestPublicTLSIsTLS13Only(t *testing.T) {
	cfg := PublicTLSConfig()
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("minimum TLS version is %x", cfg.MinVersion)
	}
}

func TestRootLifecycleRequiresAdminRole(t *testing.T) {
	for _, path := range []string{"/admin/v1/roots", "/admin/v1/roots/keyring", "/admin/v1/root-transitions/activate", "/admin/v1/root-transitions/id/retire", "/admin/v1/data-exports", "/admin/v1/data-retention/plan", "/admin/v1/data-deletions", "/admin/v1/data-holds", "/admin/v1/recovery-drills", "/admin/v1/recovery-drills/status"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if role := requiredRole(req); role != "admin" {
			t.Fatalf("path %s requires %s", path, role)
		}
	}
}

func TestAdminAuthenticationFailureIsAudited(t *testing.T) {
	c := config.Defaults()
	c.Server.AdminTransport = "tcp"
	c.Server.AllowInsecureAdmin = false
	c.AdminTLS.Enabled = true
	var eventType, actor, requestID, reason string
	handler := AdminAuthorizationWithAudit(c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthenticated request reached handler")
	}), nil, func(_ context.Context, event, identity, request, _, _, why string) {
		eventType, actor, requestID, reason = event, identity, request, why
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/products", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
	if eventType != "admin.authentication_failed" || actor != "anonymous" || requestID == "" || reason != "authentication_required" {
		t.Fatalf("audit=%q %q %q %q", eventType, actor, requestID, reason)
	}
}

func TestDataExportAuthorizationFailureIsAudited(t *testing.T) {
	c := config.Defaults()
	c.Server.AdminTransport = "tcp"
	c.AdminTLS.Enabled = true
	c.AdminAuthorization.Identities = []config.AdminIdentity{{Match: "operator", Roles: []string{"operator"}}}
	var eventType, actor, requestID, method, path, reason string
	handler := AdminAuthorizationWithAudit(c, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unauthorized export reached handler")
	}), nil, func(_ context.Context, event, identity, request, requestMethod, requestPath, why string) {
		eventType, actor, requestID, method, path, reason = event, identity, request, requestMethod, requestPath, why
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/data-exports", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "operator"}}}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || eventType != "admin.authorization_failed" || actor != "operator" || requestID == "" || method != http.MethodPost || path != "/admin/v1/data-exports" || reason != "role_required:admin" {
		t.Fatalf("status=%d audit=%q %q %q %q %q %q", rec.Code, eventType, actor, requestID, method, path, reason)
	}
}

func TestAdminRoleAuthorization(t *testing.T) {
	c := config.Defaults()
	c.Server.AdminTransport = "tcp"
	c.AdminTLS.Enabled = true
	c.AdminAuthorization.Identities = []config.AdminIdentity{{Match: "viewer", Roles: []string{"viewer"}}, {Match: "operator", Roles: []string{"operator"}}, {Match: "revoker", Roles: []string{"revoker"}}, {Match: "administrator", Roles: []string{"admin"}}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	tests := []struct {
		name, identity, method, path string
		want                         int
	}{
		{"viewer reads", "viewer", "GET", "/admin/v1/licences", 204},
		{"viewer cannot issue", "viewer", "POST", "/admin/v1/licences", 403},
		{"operator issues", "operator", "POST", "/admin/v1/licences", 204},
		{"operator reads", "operator", "GET", "/admin/v1/licences", 204},
		{"operator cannot revoke", "operator", "POST", "/admin/v1/licences/lic_1/revoke", 403},
		{"revoker revokes", "revoker", "POST", "/admin/v1/licences/lic_1/revoke", 204},
		{"operator cannot control maintenance", "operator", "POST", "/admin/v1/maintenance", 403},
		{"administrator controls maintenance", "administrator", "POST", "/admin/v1/maintenance", 204},
		{"operator cannot export data", "operator", "POST", "/admin/v1/data-exports", 403},
		{"administrator exports data", "administrator", "POST", "/admin/v1/data-exports", 204},
		{"operator cannot delete data", "operator", "POST", "/admin/v1/data-deletions", 403},
		{"administrator deletes data", "administrator", "POST", "/admin/v1/data-deletions", 204},
		{"viewer cannot inspect tombstones", "viewer", "GET", "/admin/v1/data-tombstones", 403},
		{"administrator inspects tombstones", "administrator", "GET", "/admin/v1/data-tombstones", 204},
		{"viewer cannot inspect recovery evidence", "viewer", "GET", "/admin/v1/recovery-drills", 403},
		{"administrator runs recovery drill", "administrator", "POST", "/admin/v1/recovery-drills", 204},
		{"unknown identity", "unknown", "GET", "/admin/v1/health/ready", 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: tt.identity}}}}
			w := httptest.NewRecorder()
			AdminAuthorization(c, next).ServeHTTP(w, req)
			if w.Code != tt.want {
				t.Fatalf("got %d body=%s", w.Code, w.Body.String())
			}
		})
	}
	t.Run("certificate required", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/admin/v1/health/ready", nil)
		w := httptest.NewRecorder()
		AdminAuthorization(c, next).ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("got %d", w.Code)
		}
	})
}

func TestLocalOSTransportIsAdministrative(t *testing.T) {
	c := config.Defaults()
	c.Server.AdminTransport = "named_pipe"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Actor(r.Context()) != "local-os" {
			t.Fatalf("actor=%s", Actor(r.Context()))
		}
		w.WriteHeader(204)
	})
	req := httptest.NewRequest("POST", "/admin/v1/licences/lic/revoke", nil)
	w := httptest.NewRecorder()
	AdminAuthorization(c, next).ServeHTTP(w, req)
	if w.Code != 204 {
		t.Fatalf("got %d", w.Code)
	}
}

func TestTrustedProxyRestriction(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	handler, err := TrustedProxyOnly([]string{"10.0.0.0/8"}, next)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		remote string
		proto  string
		want   int
	}{{"10.1.2.3:1234", "https", 204}, {"10.1.2.3:1234", "http", 400}, {"192.0.2.1:1234", "https", 403}} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tt.remote
		req.Header.Set("X-Forwarded-Proto", tt.proto)
		req.Header.Set("X-Forwarded-For", "198.51.100.7")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != tt.want {
			t.Fatalf("remote %s got %d", tt.remote, w.Code)
		}
	}
	t.Run("ignores spoofed addresses left of closest untrusted hop", func(t *testing.T) {
		handler, err := TrustedProxyOnly([]string{"10.0.0.0/8"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.RemoteAddr != "198.51.100.9:0" {
				t.Fatalf("remote=%s", r.RemoteAddr)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.1.2.3:1234"
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-For", "203.0.113.55, 198.51.100.9, 10.2.3.4")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status=%d", rec.Code)
		}
	})
}
