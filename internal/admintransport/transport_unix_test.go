//go:build !windows

package admintransport

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixSocketHTTP(t *testing.T) {
	name := filepath.Join(t.TempDir(), "admin.sock")
	listener, err := Listen(ListenerConfig{Transport: "unix", Address: name, SocketMode: "0600"})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })}
	defer server.Shutdown(context.Background())
	go server.Serve(listener)
	client := &http.Client{Transport: &http.Transport{DialContext: DialContext("unix", name)}, Timeout: 5 * time.Second}
	resp, err := client.Get("http://licd/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("body=%q", body)
	}
}
