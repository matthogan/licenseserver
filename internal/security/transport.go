package security

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/config"
)

func PublicTLSConfig() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS13} }

func AdminTLSConfig(c config.Config) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(c.AdminTLS.CertificateFile, c.AdminTLS.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(c.AdminTLS.ClientCAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("admin client CA contains no valid PEM certificates")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}

func AdminClientTLSConfig(c config.Config) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(c.Admin.TLS.CertificateFile, c.Admin.TLS.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("admin client certificate/key: %w", err)
	}
	pem, err := os.ReadFile(c.Admin.TLS.ServerCAFile)
	if err != nil {
		return nil, fmt.Errorf("admin server CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("admin server CA contains no valid PEM certificates")
	}
	if c.Admin.TLS.ServerName == "" {
		return nil, errors.New("admin.tls.server_name is required")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, RootCAs: pool, ServerName: c.Admin.TLS.ServerName}, nil
}

type actorKey struct{}

func Actor(ctx context.Context) string {
	actor, _ := ctx.Value(actorKey{}).(string)
	if actor == "" {
		return "admin"
	}
	return actor
}

func AdminAuthorization(c config.Config, next http.Handler, loggers ...*slog.Logger) http.Handler {
	var logger *slog.Logger
	if len(loggers) > 0 {
		logger = loggers[0]
	}
	return adminAuthorization(c, next, logger, nil)
}

type AdminAuditFunc func(context.Context, string, string, string, string, string, string)

func AdminAuthorizationWithAudit(c config.Config, next http.Handler, logger *slog.Logger, audit AdminAuditFunc) http.Handler {
	return adminAuthorization(c, next, logger, audit)
}

func adminAuthorization(c config.Config, next http.Handler, logger *slog.Logger, audit AdminAuditFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "req_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			r.Header.Set("X-Request-ID", requestID)
		}
		identity, roles, authenticated := adminIdentity(c, r)
		if !authenticated {
			if logger != nil {
				logger.Warn("admin authentication rejected", "event", "admin.authentication", "result", "failure", "reason_code", "authentication_required", "remote", r.RemoteAddr, "method", r.Method, "path", r.URL.Path)
			}
			if audit != nil {
				audit(r.Context(), "admin.authentication_failed", "anonymous", requestID, r.Method, r.URL.Path, "authentication_required")
			}
			authError(w, r, http.StatusUnauthorized, "ADMIN_AUTH_REQUIRED", "A trusted administrative identity is required.")
			return
		}
		required := requiredRole(r)
		if !hasRole(roles, required) {
			if logger != nil {
				logger.Warn("admin authorization rejected", "event", "admin.authorization", "result", "failure", "reason_code", "role_required", "identity", identity, "required_role", required, "remote", r.RemoteAddr, "method", r.Method, "path", r.URL.Path)
			}
			if audit != nil {
				audit(r.Context(), "admin.authorization_failed", identity, requestID, r.Method, r.URL.Path, "role_required:"+required)
			}
			authError(w, r, http.StatusForbidden, "ADMIN_FORBIDDEN", "The administrative identity is not permitted to perform this operation.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, identity)))
	})
}

func adminIdentity(c config.Config, r *http.Request) (string, []string, bool) {
	if c.Server.AdminTransport == "unix" || c.Server.AdminTransport == "named_pipe" {
		return "local-os", []string{"admin"}, true
	}
	if !c.AdminTLS.Enabled && c.Server.AllowInsecureAdmin {
		return "insecure-loopback", []string{"admin"}, true
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", nil, false
	}
	cert := r.TLS.PeerCertificates[0]
	for _, candidate := range certificateIdentities(cert) {
		for _, configured := range c.AdminAuthorization.Identities {
			if strings.EqualFold(configured.Match, candidate) {
				return configured.Match, configured.Roles, true
			}
		}
	}
	identities := certificateIdentities(cert)
	if len(identities) > 0 {
		return identities[0], nil, true
	}
	return "unmapped-certificate", nil, true
}

func certificateIdentities(cert *x509.Certificate) []string {
	sum := sha256.Sum256(cert.Raw)
	out := []string{"sha256:" + strings.ToLower(hex.EncodeToString(sum[:])), cert.Subject.String()}
	for _, uri := range cert.URIs {
		out = append(out, uri.String())
	}
	out = append(out, cert.DNSNames...)
	out = append(out, cert.EmailAddresses...)
	if cert.Subject.CommonName != "" {
		out = append(out, cert.Subject.CommonName)
	}
	return out
}
func requiredRole(r *http.Request) string {
	if strings.HasPrefix(r.URL.Path, "/admin/v1/data-") || strings.HasPrefix(r.URL.Path, "/admin/v1/recovery-drills") {
		return "admin"
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return "viewer"
	}
	if strings.HasSuffix(r.URL.Path, "/revoke") {
		return "revoker"
	}
	if strings.HasPrefix(r.URL.Path, "/admin/v1/issuers") || strings.HasPrefix(r.URL.Path, "/admin/v1/roots") || strings.HasPrefix(r.URL.Path, "/admin/v1/root-transitions") || r.URL.Path == "/admin/v1/maintenance" {
		return "admin"
	}
	return "operator"
}
func hasRole(roles []string, required string) bool {
	for _, role := range roles {
		if role == "admin" || role == required || (required == "viewer" && (role == "operator" || role == "revoker")) {
			return true
		}
	}
	return false
}
func authError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	id := r.Header.Get("X-Request-ID")
	if id == "" {
		id = "req_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message, "request_id": id}})
}

func TrustedProxyOnly(cidrs []string, next http.Handler) (http.Handler, error) {
	var networks []*net.IPNet
	for _, raw := range cidrs {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, err
		}
		networks = append(networks, network)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		trusted := false
		for _, network := range networks {
			if network.Contains(ip) {
				trusted = true
				break
			}
		}
		if !trusted {
			http.Error(w, "trusted reverse proxy required", http.StatusForbidden)
			return
		}
		proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
		if !strings.EqualFold(proto, "https") {
			http.Error(w, "trusted proxy must assert HTTPS", http.StatusBadRequest)
			return
		}
		forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if len(forwarded) == 0 || strings.TrimSpace(forwarded[0]) == "" {
			http.Error(w, "trusted proxy must assert a client address", http.StatusBadRequest)
			return
		}
		chain := make([]net.IP, 0, len(forwarded))
		for _, raw := range forwarded {
			forwardedIP := net.ParseIP(strings.TrimSpace(raw))
			if forwardedIP == nil {
				http.Error(w, "invalid forwarded client address", http.StatusBadRequest)
				return
			}
			chain = append(chain, forwardedIP)
		}
		// Walk inward from the trusted peer. The closest untrusted hop is the
		// client; values to its left are untrusted input and are ignored.
		client := chain[0]
		for i := len(chain) - 1; i >= 0; i-- {
			client = chain[i]
			if !ipInNetworks(client, networks) {
				break
			}
		}
		r.RemoteAddr = net.JoinHostPort(client.String(), "0")
		next.ServeHTTP(w, r)
	}), nil
}

func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func PublicSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
