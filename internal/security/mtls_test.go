package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/matthogan/licenceserver/internal/config"
)

func TestMutualTLSAndRoleMapping(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := newCA(t)
	serverCert, serverKey := newCertificate(t, caCert, caKey, "licd-admin", true, nil)
	identity, _ := url.Parse("spiffe://example.test/licensing/operator")
	clientCert, clientKey := newCertificate(t, caCert, caKey, "operator", false, []*url.URL{identity})
	caFile := writeCertificate(t, dir, "ca.crt", caCert.Raw)
	serverCertFile, serverKeyFile := writePair(t, dir, "server", serverCert.Raw, serverKey)
	clientCertFile, clientKeyFile := writePair(t, dir, "client", clientCert.Raw, clientKey)
	c := config.Defaults()
	c.Server.AdminTransport = "tcp"
	c.AdminTLS.Enabled = true
	c.AdminTLS.CertificateFile = serverCertFile
	c.AdminTLS.PrivateKeyFile = serverKeyFile
	c.AdminTLS.ClientCAFile = caFile
	c.AdminAuthorization.Identities = []config.AdminIdentity{{Match: identity.String(), Roles: []string{"viewer", "operator"}}}
	serverTLS, err := AdminTLSConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(AdminAuthorization(c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	c.Admin.Transport = "tcp"
	c.Admin.URL = server.URL
	c.Admin.TLS.CertificateFile = clientCertFile
	c.Admin.TLS.PrivateKeyFile = clientKeyFile
	c.Admin.TLS.ServerCAFile = caFile
	c.Admin.TLS.ServerName = "localhost"
	clientTLS, err := AdminClientTLSConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/admin/v1/licences", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("operator status=%d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/admin/v1/issuers/rotate", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("issuer rotation status=%d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, server.URL+"/admin/v1/issuers", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("issuer list status=%d", resp.StatusCode)
	}
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("TLS version=%x", resp.TLS.Version)
	}
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/admin/v1/licences/lic_1/revoke", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("revoke status=%d", resp.StatusCode)
	}
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: clientTLS.RootCAs, ServerName: "localhost"}}}
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/admin/v1/health/ready", nil)
	if _, err = noCert.Do(req); err == nil {
		t.Fatal("server accepted a client without a certificate")
	}
}

func TestPublicListenerRejectsTLS12(t *testing.T) {
	ca, caKey := newCA(t)
	serverCert, serverKey := newCertificate(t, ca, caKey, "public", true, nil)
	server := httptest.NewUnstartedServer(PublicSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	server.TLS = PublicTLSConfig()
	server.TLS.Certificates = []tls.Certificate{{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey}}
	server.StartTLS()
	defer server.Close()
	tls12Client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true}}}
	if _, err := tls12Client.Get(server.URL); err == nil {
		t.Fatal("TLS 1.2 connection succeeded")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	tls13Client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost"}}}
	resp, err := tls13Client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("version=%x", resp.TLS.Version)
	}
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("missing HSTS header")
	}
}

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
func newCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, server bool, uris []*url.URL) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage, URIs: uris}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
func writeCertificate(t *testing.T, dir, name string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func writePair(t *testing.T, dir, name string, certDER []byte, key *ecdsa.PrivateKey) (string, string) {
	t.Helper()
	cert := writeCertificate(t, dir, name+".crt", certDER)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, name+".key")
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, keyPath
}
