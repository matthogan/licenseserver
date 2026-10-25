package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoHeadersSendsIdempotencyKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Idempotency-Key"); got != "request-000000000001" {
			t.Errorf("Idempotency-Key=%q", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["code"] != "secret-code" {
			t.Errorf("body=%v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()
	var out map[string]string
	err := New(server.URL).DoHeaders(context.Background(), http.MethodPost, "/v1/activations", map[string]string{"code": "secret-code"}, &out, map[string]string{"Idempotency-Key": "request-000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	if out["status"] != "ok" {
		t.Fatalf("out=%v", out)
	}
}

func TestDownloadStreamsSuccessfulBody(t *testing.T) {
	payload := []byte("deterministic-export-archive")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/admin/v1/data-exports" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	var destination bytes.Buffer
	if _, err := New(server.URL).Download(context.Background(), http.MethodPost, "/admin/v1/data-exports", map[string]string{"product_id": "product"}, &destination); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(destination.Bytes(), payload) {
		t.Fatalf("body=%q", destination.Bytes())
	}
}
